//! Serveur RPC : accepte des connexions TCP, parse HTTP, dispatch JSON-RPC.

use std::io::BufReader;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::backend::RpcBackend;
use crate::http::{read_request, write_error, write_json_ok, HttpError};

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
        })
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
        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                return Ok(());
            }
            match self.listener.accept() {
                Ok((stream, _peer)) => {
                    let backend = Arc::clone(&self.backend);
                    thread::spawn(move || {
                        let _ = handle_connection(stream, backend, idle_timeout, max_requests);
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

fn handle_connection<B: RpcBackend>(
    stream: TcpStream,
    backend: Arc<B>,
    idle_timeout: Duration,
    max_requests: usize,
) -> std::io::Result<()> {
    // Timeouts sur lecture/écriture. Le `WouldBlock`/`TimedOut` est
    // traduit en `HttpError::request_timeout` dans `read_request`.
    stream.set_read_timeout(Some(idle_timeout)).ok();
    stream.set_write_timeout(Some(idle_timeout)).ok();

    // Le `BufReader` persiste sur toute la connexion (keep-alive) : il
    // contient les bytes déjà lus qui appartiennent à la requête suivante.
    let mut reader = BufReader::new(stream);
    let mut served: usize = 0;

    loop {
        if served >= max_requests {
            // Limite atteinte : fermer proprement.
            return Ok(());
        }

        let req = match read_request(&mut reader) {
            Ok(None) => return Ok(()), // EOF propre.
            Ok(Some(r)) => r,
            Err(e) if e.status == 408 => return Ok(()), // timeout silencieux
            Err(e) => {
                let _ = write_error(reader.get_mut(), &e, false);
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
            return Ok(());
        }
        if !keep_alive {
            return Ok(());
        }
    }
}
