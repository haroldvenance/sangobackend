//! Serveur HTTP/1.1 minimal.
//!
//! Ne gère que :
//!
//! - la méthode `POST` sur `/rpc` ;
//! - le header `Content-Length` ;
//! - une réponse `200 OK` avec `Content-Type: application/json`.
//!
//! Pas de keep-alive, pas de chunked encoding, pas de TLS.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;

/// Requête HTTP parsée.
#[derive(Debug)]
pub struct HttpRequest {
    /// Méthode (`POST`, `GET`).
    pub method: String,
    /// Chemin (`/rpc`).
    pub path: String,
    /// Corps brut.
    pub body: Vec<u8>,
}

/// Erreur HTTP (renvoyée au client).
#[derive(Debug)]
pub struct HttpError {
    /// Code HTTP.
    pub status: u16,
    /// Raison.
    pub reason: &'static str,
    /// Message.
    pub message: String,
}

impl HttpError {
    /// 400 Bad Request.
    #[must_use]
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self {
            status: 400,
            reason: "Bad Request",
            message: msg.into(),
        }
    }

    /// 404 Not Found.
    #[must_use]
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self {
            status: 404,
            reason: "Not Found",
            message: msg.into(),
        }
    }

    /// 405 Method Not Allowed.
    #[must_use]
    pub fn method_not_allowed(msg: impl Into<String>) -> Self {
        Self {
            status: 405,
            reason: "Method Not Allowed",
            message: msg.into(),
        }
    }

    /// 413 Payload Too Large.
    #[must_use]
    pub fn payload_too_large(msg: impl Into<String>) -> Self {
        Self {
            status: 413,
            reason: "Payload Too Large",
            message: msg.into(),
        }
    }
}

/// Taille maximale d'un corps HTTP (1 MiB).
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Lit une requête HTTP depuis un stream.
pub fn read_request(stream: &mut TcpStream) -> Result<HttpRequest, HttpError> {
    let mut reader = BufReader::new(
        stream
            .try_clone()
            .map_err(|e| HttpError::bad_request(format!("stream clone: {e}")))?,
    );

    // Ligne de requête.
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .map_err(|e| HttpError::bad_request(format!("read request line: {e}")))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| HttpError::bad_request("missing method"))?
        .to_string();
    let path = parts
        .next()
        .ok_or_else(|| HttpError::bad_request("missing path"))?
        .to_string();
    // Version ignorée.

    // Headers.
    let mut content_length: Option<usize> = None;
    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|e| HttpError::bad_request(format!("read header: {e}")))?;
        if line == "\r\n" || line == "\n" {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("content-length:") {
            content_length = Some(
                rest.trim()
                    .parse()
                    .map_err(|e| HttpError::bad_request(format!("bad content-length: {e}")))?,
            );
        }
    }

    let len = content_length.unwrap_or(0);
    if len > MAX_BODY_BYTES {
        return Err(HttpError::payload_too_large(format!(
            "body length {len} exceeds {MAX_BODY_BYTES}"
        )));
    }

    let mut body = vec![0u8; len];
    if len > 0 {
        reader
            .read_exact(&mut body)
            .map_err(|e| HttpError::bad_request(format!("read body: {e}")))?;
    }

    Ok(HttpRequest { method, path, body })
}

/// Envoie une réponse HTTP 200 avec un corps JSON.
pub fn write_json_ok(stream: &mut TcpStream, body: &[u8]) -> std::io::Result<()> {
    let header = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

/// Envoie une réponse HTTP d'erreur.
pub fn write_error(stream: &mut TcpStream, err: &HttpError) -> std::io::Result<()> {
    let body = format!("{}\n", err.message);
    let header = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        err.status,
        err.reason,
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    /// Crée un serveur jetable, envoie `raw`, retourne la réponse brute.
    fn round_trip(raw: &[u8]) -> Vec<u8> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let payload = raw.to_vec();

        // Client.
        let client = std::thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            s.write_all(&payload).unwrap();
            s.shutdown(std::net::Shutdown::Write).unwrap();
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf);
            buf
        });

        // Serveur (une seule requête).
        let (mut stream, _) = listener.accept().unwrap();
        let req = read_request(&mut stream).expect("parse");
        write_json_ok(&mut stream, b"{\"ok\":true}").unwrap();
        drop(stream);

        let _ = req;
        client.join().unwrap()
    }

    #[test]
    fn parses_post_with_json_body() {
        let raw = b"POST /rpc HTTP/1.1\r\nContent-Length: 12\r\n\r\n{\"hello\":1}\n";
        let resp = round_trip(raw);
        let s = String::from_utf8_lossy(&resp);
        assert!(s.contains("200 OK"));
        assert!(s.contains("Content-Type: application/json"));
        assert!(s.contains("\"ok\":true"));
    }

    #[test]
    fn rejects_oversized_body() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let client = std::thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            let header = format!(
                "POST /rpc HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
                MAX_BODY_BYTES + 1
            );
            let _ = s.write_all(header.as_bytes());
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf);
            buf
        });

        let (mut stream, _) = listener.accept().unwrap();
        match read_request(&mut stream) {
            Err(e) => {
                assert_eq!(e.status, 413);
                write_error(&mut stream, &e).unwrap();
            }
            Ok(_) => panic!("devrait rejeter"),
        }
        drop(stream);
        let _ = client.join();
    }
}
