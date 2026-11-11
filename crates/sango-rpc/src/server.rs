//! Serveur RPC : accepte des connexions TCP, parse HTTP, dispatch JSON-RPC.

use std::collections::HashMap;
use std::io::{BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rustls::{ServerConnection, StreamOwned};

use crate::backend::RpcBackend;
use crate::http::{read_request, write_error, write_json_ok, write_preflight_ok, HttpError};
use crate::tls::TlsConfig;

/// Nombre maximal de connexions simultanées (protection OOM).
const DEFAULT_MAX_CONNECTIONS: usize = 256;

/// Cap dur sur le nombre de messages d'un batch (protection body DoS).
pub const MAX_BATCH_SIZE: usize = 100;

/// Token bucket par IP.
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new() -> Self {
        Self {
            tokens: 30.0, // rafale initiale
            last_refill: Instant::now(),
        }
    }

    /// Consomme 1 token. `true` = autorisé.
    fn try_consume(&mut self, rate_per_sec: f64, capacity: f64) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * rate_per_sec).min(capacity);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Limiteur global (IP → token bucket), thread-safe.
pub struct RateLimiter {
    buckets: Mutex<HashMap<IpAddr, TokenBucket>>,
    rate_per_sec: f64,
    capacity: f64,
    last_cleanup: Mutex<Instant>,
}

impl RateLimiter {
    pub fn new(rate_per_sec: f64, capacity: f64) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            rate_per_sec,
            capacity,
            last_cleanup: Mutex::new(Instant::now()),
        }
    }

    /// Autorise ou non `ip`. Purge les buckets inactifs (> 1h) toutes les 10 min.
    pub fn allow(&self, ip: IpAddr) -> bool {
        {
            let mut guard = self.buckets.lock().unwrap();
            let bucket = guard.entry(ip).or_insert_with(TokenBucket::new);
            if !bucket.try_consume(self.rate_per_sec, self.capacity) {
                return false;
            }
        }

        // Cleanup périodique (throttlé à 10 min).
        let mut last = self.last_cleanup.lock().unwrap();
        if last.elapsed() > Duration::from_secs(600) {
            let mut guard = self.buckets.lock().unwrap();
            let now = Instant::now();
            guard.retain(|_, b| now.duration_since(b.last_refill).as_secs() < 3600);
            *last = now;
        }
        true
    }
}

/// Serveur RPC.
pub struct RpcServer<B: RpcBackend> {
    listener: TcpListener,
    backend: Arc<B>,
    shutdown: Arc<AtomicBool>,
    idle_timeout: Duration,
    max_requests_per_connection: usize,
    tls: Option<TlsConfig>,
    /// Compteur de connexions actives.
    active_connections: Arc<AtomicUsize>,
    max_connections: usize,
    /// Rate limiter par IP.
    rate_limiter: Arc<RateLimiter>,
}

impl<B: RpcBackend> RpcServer<B> {
    pub fn bind(addr: SocketAddr, backend: Arc<B>) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            backend,
            shutdown: Arc::new(AtomicBool::new(false)),
            idle_timeout: Duration::from_secs(30),
            max_requests_per_connection: 100,
            tls: None,
            active_connections: Arc::new(AtomicUsize::new(0)),
            max_connections: DEFAULT_MAX_CONNECTIONS,
            // 20 req/s par IP, rafale 30.
            rate_limiter: Arc::new(RateLimiter::new(20.0, 30.0)),
        })
    }

    pub fn bind_tls(addr: SocketAddr, backend: Arc<B>, tls: TlsConfig) -> std::io::Result<Self> {
        let mut server = Self::bind(addr, backend)?;
        server.tls = Some(tls);
        Ok(server)
    }

    #[must_use]
    pub fn with_idle_timeout(mut self, d: Duration) -> Self {
        self.idle_timeout = d;
        self
    }

    #[must_use]
    pub fn with_max_requests(mut self, n: usize) -> Self {
        self.max_requests_per_connection = n;
        self
    }

    #[must_use]
    pub fn with_max_connections(mut self, n: usize) -> Self {
        self.max_connections = n;
        self
    }

    #[must_use]
    pub fn with_rate_limit(mut self, rate_per_sec: f64, capacity: f64) -> Self {
        self.rate_limiter = Arc::new(RateLimiter::new(rate_per_sec, capacity));
        self
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    #[must_use]
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            flag: Arc::clone(&self.shutdown),
        }
    }

    pub fn serve(self) -> std::io::Result<()> {
        let idle_timeout = self.idle_timeout;
        let max_requests = self.max_requests_per_connection;
        let tls = self.tls;
        let active = Arc::clone(&self.active_connections);
        let max_conn = self.max_connections;
        let rate_limiter = Arc::clone(&self.rate_limiter);

        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                return Ok(());
            }
            match self.listener.accept() {
                Ok((stream, peer)) => {
                    // === Backpressure : rejeter si max atteint ===
                    let current = active.fetch_add(1, Ordering::Relaxed);
                    if current >= max_conn {
                        active.fetch_sub(1, Ordering::Relaxed);
                        // Trop de connexions : on ferme sans réponse.
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        continue;
                    }

                    // === Rate limit par IP (avant spawn) ===
                    if !rate_limiter.allow(peer.ip()) {
                        active.fetch_sub(1, Ordering::Relaxed);
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        continue;
                    }

                    let backend = Arc::clone(&self.backend);
                    let tls = tls.clone();
                    let active_clone = Arc::clone(&active);
                    thread::spawn(move || {
                        let _ = serve_one_connection(
                            stream,
                            backend,
                            idle_timeout,
                            max_requests,
                            tls,
                        );
                        active_clone.fetch_sub(1, Ordering::Relaxed);
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => return Err(e),
            }
        }
    }
}

#[derive(Clone)]
pub struct ShutdownHandle {
    flag: Arc<AtomicBool>,
}

impl ShutdownHandle {
    pub fn shutdown(&self) {
        self.flag.store(true, Ordering::Relaxed);
    }
}

fn serve_one_connection<B: RpcBackend>(
    tcp: TcpStream,
    backend: Arc<B>,
    idle_timeout: Duration,
    max_requests: usize,
    tls: Option<TlsConfig>,
) -> std::io::Result<()> {
    tcp.set_read_timeout(Some(idle_timeout)).ok();
    tcp.set_write_timeout(Some(idle_timeout)).ok();

    match tls {
        Some(cfg) => {
            let conn = ServerConnection::new(cfg.server_config())
                .map_err(|e| std::io::Error::other(format!("tls: {e}")))?;
            let stream = StreamOwned::new(conn, tcp);
            handle_connection(stream, backend, max_requests)
        }
        None => handle_connection(tcp, backend, max_requests),
    }
}

trait GracefulShutdown {
    fn graceful_close(&mut self);
}

impl GracefulShutdown for TcpStream {
    fn graceful_close(&mut self) {
        let _ = self.shutdown(std::net::Shutdown::Write);
    }
}

impl GracefulShutdown for StreamOwned<ServerConnection, TcpStream> {
    fn graceful_close(&mut self) {
        self.conn.send_close_notify();
        let _ = self.flush();
        let _ = self.sock.shutdown(std::net::Shutdown::Write);
    }
}

fn handle_connection<S, B>(stream: S, backend: Arc<B>, max_requests: usize) -> std::io::Result<()>
where
    S: Read + Write + GracefulShutdown,
    B: RpcBackend,
{
    let mut reader = BufReader::new(stream);
    let mut served: usize = 0;

    loop {
        if served >= max_requests {
            reader.get_mut().graceful_close();
            return Ok(());
        }

        let req = match read_request(&mut reader) {
            Ok(None) => {
                reader.get_mut().graceful_close();
                return Ok(());
            }
            Ok(Some(r)) => r,
            Err(e) if e.status == 408 => {
                reader.get_mut().graceful_close();
                return Ok(());
            }
            Err(e) => {
                let _ = write_error(reader.get_mut(), &e, false);
                reader.get_mut().graceful_close();
                return Ok(());
            }
        };
        served += 1;
        let keep_alive = req.keep_alive && served < max_requests;

        if req.method == "OPTIONS" {
            if write_preflight_ok(reader.get_mut(), keep_alive, "POST, OPTIONS").is_err() {
                reader.get_mut().graceful_close();
                return Ok(());
            }
            if !keep_alive {
                return Ok(());
            }
            continue;
        }

        if req.method != "POST" {
            let err = HttpError::method_not_allowed(format!("method {} not allowed", req.method));
            if write_error(reader.get_mut(), &err, keep_alive).is_err() {
                reader.get_mut().graceful_close();
                return Ok(());
            }
            if !keep_alive {
                return Ok(());
            }
            continue;
        }

        if req.path != "/rpc" && req.path != "/" {
            let err = HttpError::not_found(format!("path {} not found", req.path));
            if write_error(reader.get_mut(), &err, keep_alive).is_err() {
                reader.get_mut().graceful_close();
                return Ok(());
            }
            if !keep_alive {
                return Ok(());
            }
            continue;
        }

        let json_value: serde_json::Value = match serde_json::from_slice(&req.body) {
            Ok(v) => v,
            Err(e) => {
                let resp = serde_json::json!({
                    "jsonrpc": "2.0",
                    "error": { "code": -32600, "message": format!("parse json: {e}") },
                    "id": serde_json::Value::Null,
                });
                let body = serde_json::to_vec(&resp).unwrap_or_default();
                if write_json_ok(reader.get_mut(), &body, keep_alive).is_err() {
                    reader.get_mut().graceful_close();
                    return Ok(());
                }
                if !keep_alive {
                    return Ok(());
                }
                continue;
            }
        };

        // === Cap batch size (DoS via 10k items) ===
        if let serde_json::Value::Array(ref items) = json_value {
            if items.len() > MAX_BATCH_SIZE {
                let resp = serde_json::json!({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32600,
                        "message": format!("batch size {} exceeds {}", items.len(), MAX_BATCH_SIZE)
                    },
                    "id": serde_json::Value::Null,
                });
                let body = serde_json::to_vec(&resp).unwrap_or_default();
                if write_json_ok(reader.get_mut(), &body, keep_alive).is_err() {
                    reader.get_mut().graceful_close();
                    return Ok(());
                }
                if !keep_alive {
                    return Ok(());
                }
                continue;
            }
        }

        let resp = crate::dispatch::dispatch_value(&*backend, json_value);
        let body = serde_json::to_vec(&resp).unwrap_or_default();
        if write_json_ok(reader.get_mut(), &body, keep_alive).is_err() {
            reader.get_mut().graceful_close();
            return Ok(());
        }
        if !keep_alive {
            return Ok(());
        }
    }
}