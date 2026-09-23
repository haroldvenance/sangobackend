//! Serveur RPC : accepte des connexions TCP, parse HTTP, dispatch JSON-RPC.

use std::io::Write as _;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::backend::RpcBackend;
use crate::dispatch::dispatch;
use crate::http::{read_request, write_error, write_json_ok, HttpError};
use crate::json::{Request, Response};

/// Serveur RPC.
pub struct RpcServer<B: RpcBackend> {
    listener: TcpListener,
    backend: Arc<B>,
    shutdown: Arc<AtomicBool>,
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
        })
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
        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                return Ok(());
            }
            match self.listener.accept() {
                Ok((stream, _peer)) => {
                    let backend = Arc::clone(&self.backend);
                    thread::spawn(move || {
                        let _ = handle_connection(stream, backend);
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

fn handle_connection<B: RpcBackend>(mut stream: TcpStream, backend: Arc<B>) -> std::io::Result<()> {
    let req = match read_request(&mut stream) {
        Ok(r) => r,
        Err(e) => {
            let _ = write_error(&mut stream, &e);
            return Ok(());
        }
    };

    if req.method != "POST" {
        let _ = write_error(
            &mut stream,
            &HttpError::method_not_allowed(format!("method {} not allowed", req.method)),
        );
        return Ok(());
    }

    // On accepte /rpc et / (le test utilise /rpc).
    if req.path != "/rpc" && req.path != "/" {
        let _ = write_error(
            &mut stream,
            &HttpError::not_found(format!("path {} not found", req.path)),
        );
        return Ok(());
    }

    // Parser le JSON.
    let json_req: Request = match serde_json::from_slice(&req.body) {
        Ok(r) => r,
        Err(e) => {
            let resp = Response::failure(
                serde_json::Value::Null,
                crate::error::RpcError::InvalidRequest(format!("parse json: {e}")),
            );
            let body = serde_json::to_vec(&resp).unwrap_or_default();
            return write_json_ok(&mut stream, &body);
        }
    };

    let resp = dispatch(&*backend, json_req);
    let body = serde_json::to_vec(&resp).unwrap_or_default();
    let _ = stream.write_all(b"");
    write_json_ok(&mut stream, &body)
}
