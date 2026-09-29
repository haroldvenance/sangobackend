//! Serveur HTTP minimal pour `/metrics` (Prometheus).
//!
//! ## Pourquoi un serveur séparé
//!
//! Prometheus scrape via un `GET text/plain`. Le serveur RPC
//! (`sango-rpc`) ne sert que du JSON-RPC `POST`. On ne mélange pas les
//! deux protocoles dans le même port :
//!
//! - règles CORS différentes (RPC = `*`, metrics = aucune) ;
//! - scraping sur un réseau interne (Docker) sans exposer le RPC public ;
//! - séparation claire des surfaces d'attaque.
//!
//! ## Réutilisation
//!
//! On réutilise `sango_rpc::http::read_request` pour le parsing HTTP/1.1
//! (headers, content-length, timeouts). Le serveur ne répond qu'à
//! `GET /metrics`, tout autre chemin retourne `404`.
//!
//! ## Format de réponse
//!
//! `Content-Type: text/plain; version=0.0.4` — format d'exposition
//! Prometheus standard.

use std::io::{BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use sango_rpc::http::read_request;

use crate::metrics;

/// Timeout de lecture/écriture par connexion.
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Serveur Prometheus (bloquant, à lancer dans un thread).
pub struct MetricsServer {
    listener: TcpListener,
}

impl MetricsServer {
    /// Bind sur `addr`.
    pub fn bind(addr: SocketAddr) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        Ok(Self { listener })
    }

    /// Adresse locale effective.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Boucle de service (bloquant).
    ///
    /// Une thread par connexion. Le nombre de scrapers est faible, pas
    /// besoin de pool.
    pub fn serve(self) -> std::io::Result<()> {
        for stream in self.listener.incoming() {
            match stream {
                Ok(s) => {
                    thread::spawn(move || {
                        let _ = handle(s);
                    });
                }
                Err(e) => eprintln!("metrics accept: {e}"),
            }
        }
        Ok(())
    }
}

fn handle(stream: TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT)).ok();
    stream.set_write_timeout(Some(IO_TIMEOUT)).ok();

    let mut reader = BufReader::new(stream);
    let req = match read_request(&mut reader) {
        Ok(Some(r)) => r,
        _ => return Ok(()),
    };

    if req.method != "GET" || req.path != "/metrics" {
        return write_response(
            reader.get_mut(),
            404,
            "Not Found",
            "text/plain",
            b"not found\n",
        );
    }

    let body = match metrics::render() {
        Some(s) => s,
        None => String::from("# metrics not initialized\n"),
    };

    write_response(
        reader.get_mut(),
        200,
        "OK",
        "text/plain; version=0.0.4",
        body.as_bytes(),
    )
}

fn write_response<W: Write>(
    stream: &mut W,
    status: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let header = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: {}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        status,
        reason,
        content_type,
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;

    fn spawn_server() -> SocketAddr {
        let _ = metrics::init_metrics();
        let server = MetricsServer::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.serve();
        });
        // Attente courte pour que le listener soit prêt.
        thread::sleep(Duration::from_millis(50));
        addr
    }

    fn get(addr: SocketAddr, path: &str) -> String {
        let mut s = TcpStream::connect(addr).unwrap();
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            path
        );
        s.write_all(req.as_bytes()).unwrap();
        s.shutdown(std::net::Shutdown::Write).ok();
        let mut buf = String::new();
        s.read_to_string(&mut buf).unwrap();
        buf
    }

    #[test]
    fn metrics_endpoint_returns_text() {
        let addr = spawn_server();
        let resp = get(addr, "/metrics");
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
        assert!(
            resp.contains("Content-Type: text/plain; version=0.0.4"),
            "got: {resp}"
        );
    }

    #[test]
    fn unknown_path_returns_404() {
        let addr = spawn_server();
        let resp = get(addr, "/foo");
        assert!(resp.starts_with("HTTP/1.1 404"), "got: {resp}");
    }
}
