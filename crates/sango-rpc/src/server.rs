//! Serveur RPC : accepte des connexions TCP, parse HTTP, dispatch JSON-RPC.

use std::io::{BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustls::{ServerConnection, StreamOwned};

use crate::backend::RpcBackend;
use crate::http::{read_request, write_error, write_json_ok, HttpError};
use crate::tls::TlsConfig;

/// Serveur RPC.
pub struct RpcServer<B: RpcBackend> {
    listener: TcpListener,
    backend: Arc<B>,
    shutdown: Arc<AtomicBool>,
    /// Timeout d'inactivité sur chaque connexion (keep-alive).
    idle_timeout: Duration,
    /// Nombre maximal de requêtes servies sur une même connexion
    /// (protection anti-DoS).
    max_requests_per_connection: usize,
    /// Configuration TLS. `None` → HTTP en clair.
    tls: Option<TlsConfig>,
}

impl<B: RpcBackend> RpcServer<B> {
    /// Bind sur `addr`.
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
        })
    }

    /// Bind sur `addr` avec **TLS** activé.
    ///
    /// - Le serveur s'authentifie auprès du client (TLS one-way).
    /// - Le client n'est pas authentifié par cert.
    pub fn bind_tls(addr: SocketAddr, backend: Arc<B>, tls: TlsConfig) -> std::io::Result<Self> {
        let mut server = Self::bind(addr, backend)?;
        server.tls = Some(tls);
        Ok(server)
    }

    /// Configure le timeout d'inactivité (keep-alive).
    ///
    /// Au-delà, la connexion est fermée sans réponse (408 silencieux côté
    /// client, qui verra juste la connexion tomber).
    #[must_use]
    pub fn with_idle_timeout(mut self, d: Duration) -> Self {
        self.idle_timeout = d;
        self
    }

    /// Configure le nombre maximal de requêtes servies sur une même
    /// connexion (protection anti-DoS).
    #[must_use]
    pub fn with_max_requests(mut self, n: usize) -> Self {
        self.max_requests_per_connection = n;
        self
    }

    /// Adresse locale effective.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Handle de shutdown.
    #[must_use]
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            flag: Arc::clone(&self.shutdown),
        }
    }

    /// Boucle de service (bloquant).
    ///
    /// Retourne quand `shutdown()` a été appelé via un [`ShutdownHandle`].
    pub fn serve(self) -> std::io::Result<()> {
        let idle_timeout = self.idle_timeout;
        let max_requests = self.max_requests_per_connection;
        let tls = self.tls;
        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                return Ok(());
            }
            match self.listener.accept() {
                Ok((stream, _peer)) => {
                    let backend = Arc::clone(&self.backend);
                    let tls = tls.clone();
                    thread::spawn(move || {
                        let _ =
                            serve_one_connection(stream, backend, idle_timeout, max_requests, tls);
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

/// Handle pour demander l'arrêt du serveur.
#[derive(Clone)]
pub struct ShutdownHandle {
    flag: Arc<AtomicBool>,
}

impl ShutdownHandle {
    /// Demande l'arrêt. Le serveur s'arrêtera à la prochaine itération.
    pub fn shutdown(&self) {
        self.flag.store(true, Ordering::Relaxed);
    }
}

/// Sert une connexion TCP : applique TLS si configuré, puis délègue
/// à la boucle keep-alive.
fn serve_one_connection<B: RpcBackend>(
    tcp: TcpStream,
    backend: Arc<B>,
    idle_timeout: Duration,
    max_requests: usize,
    tls: Option<TlsConfig>,
) -> std::io::Result<()> {
    // Timeouts TCP : à poser **avant** le wrap TLS pour qu'ils s'appliquent
    // au socket sous-jacent.
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

/// Boucle keep-alive générique sur un stream (`TcpStream` ou
/// `StreamOwned<ServerConnection, TcpStream>`).
/// Trait pour fermer proprement un stream, TLS ou non.
///
/// - `TcpStream` : `shutdown(Write)` envoie FIN.
/// - `StreamOwned<ServerConnection, TcpStream>` : envoie `close_notify` TLS
///   puis FIN. Sans ce close_notify, certains clients (rustls inclus)
///   remontent une erreur `peer closed connection without sending TLS
///   close_notify` quand ils font `read_to_end`.
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
    // Le `BufReader` persiste sur toute la connexion (keep-alive) : il
    // contient les bytes déjà lus qui appartiennent à la requête suivante.
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
                return Ok(()); // EOF propre.
            }
            Ok(Some(r)) => r,
            Err(e) if e.status == 408 => {
                reader.get_mut().graceful_close();
                return Ok(()); // timeout silencieux
            }
            Err(e) => {
                let _ = write_error(reader.get_mut(), &e, false);
                reader.get_mut().graceful_close();
                return Ok(());
            }
        };
        served += 1;

        // Dernière requête autorisée ou client demande close → fermer.
        let keep_alive = req.keep_alive && served < max_requests;

        // Méthode.
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

        // Chemin.
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

        // Parser le JSON brut en `Value` (objet unique OU tableau batch).
        let json_value: serde_json::Value = match serde_json::from_slice(&req.body) {
            Ok(v) => v,
            Err(e) => {
                let resp = serde_json::json!({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32600,
                        "message": format!("parse json: {e}")
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
        };

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
