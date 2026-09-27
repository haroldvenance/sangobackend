//! Serveur HTTP/1.1 minimal avec keep-alive.
//!
//! ## Support
//!
//! - `POST /rpc` (et `/`)
//! - `Content-Type: application/json`
//! - `Content-Length` obligatoire
//! - Body max 1 MiB
//! - **Keep-alive** : une même connexion TCP peut servir N requêtes
//!   successives (`Connection: keep-alive`, défaut HTTP/1.1)
//! - Détection `Connection: close` → ferme après la réponse
//! - Timeout d'inactivité configurable côté serveur (voir `server.rs`)
//!
//! ## Non supporté (V1)
//!
//! - TLS (étape A2 ultérieure)
//! - Chunked transfer-encoding
//! - HTTP/2
//!
//! ## Contrat sur `read_request`
//!
//! Le `BufReader<TcpStream>` **doit persister** entre les appels sur une
//! même connexion : il contient le buffer des bytes déjà lus (headers +
//! début du body suivant). Recréer un `BufReader` à chaque appel casserait
//! le keep-alive en perdant ces bytes.

use std::io::{BufRead, BufReader, Read, Write};

/// Requête HTTP parsée.
#[derive(Debug)]
pub struct HttpRequest {
    /// Méthode (`POST`, `GET`).
    pub method: String,
    /// Chemin (`/rpc`).
    pub path: String,
    /// Corps brut.
    pub body: Vec<u8>,
    /// Vrai si le client accepte que la connexion soit réutilisée.
    ///
    /// - HTTP/1.1 : `true` par défaut.
    /// - `Connection: close` : `false`.
    pub keep_alive: bool,
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

    /// 408 Request Timeout.
    ///
    /// Utilisé quand le serveur a atteint son `idle_timeout` sans avoir lu
    /// la ligne de requête complète. Le serveur peut alors fermer la
    /// connexion sans écrire de réponse.
    #[must_use]
    pub fn request_timeout() -> Self {
        Self {
            status: 408,
            reason: "Request Timeout",
            message: "idle timeout exceeded".into(),
        }
    }
}

/// Taille maximale d'un corps HTTP (1 MiB).
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Headers CORS envoyés sur **toutes** les réponses.
///
/// ## Pourquoi `*`
///
/// Pour V1, on accepte n'importe quelle origine. C'est acceptable pour
/// un RPC public sans état d'authentification : les clients signent
/// localement, le nœud ne valide que des signatures. Ne pas exposer
/// d'endpoint stateful (wallet custodial) avec `Access-Control-Allow-Origin: *`.
///
/// Pour une allow-list en P4+, remplacer par une origine explicite.
pub const CORS_ALLOW_ORIGIN: &str = "*";

/// Méthodes autorisées en CORS (`Access-Control-Allow-Methods`).
///
/// Seul `POST` est réellement utilisé par le RPC ; `OPTIONS` sert au
/// preflight navigateur.
pub const CORS_ALLOW_METHODS: &str = "POST, OPTIONS";

/// En-têtes autorisés en CORS (`Access-Control-Allow-Headers`).
pub const CORS_ALLOW_HEADERS: &str = "Content-Type, Accept, Authorization";

/// Durée de cache du preflight CORS en secondes (`Access-Control-Max-Age`).
///
/// `86400` = 24 heures : les navigateurs ne rejouent pas le preflight
/// avant une journée, ce qui évite un aller-retour par requête.
pub const CORS_MAX_AGE: &str = "86400"; // 24h

/// Vrai si l'erreur d'I/O est un timeout de lecture.
fn is_timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// Lit une requête HTTP depuis un reader persistant.
///
/// ## Retour
///
/// - `Ok(None)` : EOF propre (le client a fermé la connexion avant
///   d'envoyer une requête). Appelant doit fermer proprement.
/// - `Ok(Some(req))` : requête lue.
/// - `Err(e)` : erreur de parsing ou timeout. Voir `e.status`.
///
/// ## Limites
///
/// - Body > `MAX_BODY_BYTES` → `HttpError::payload_too_large` (413).
/// - Timeout d'idle (dépassé côté serveur) → `HttpError::request_timeout` (408).
pub fn read_request<S: Read>(reader: &mut BufReader<S>) -> Result<Option<HttpRequest>, HttpError> {
    // Ligne de requête.
    let mut request_line = String::new();
    match reader.read_line(&mut request_line) {
        Ok(0) => return Ok(None), // EOF propre avant toute donnée.
        Ok(_) => {}
        Err(e) if is_timeout(&e) => return Err(HttpError::request_timeout()),
        Err(e) => return Err(HttpError::bad_request(format!("read request line: {e}"))),
    }
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| HttpError::bad_request("missing method"))?
        .to_string();
    let path = parts
        .next()
        .ok_or_else(|| HttpError::bad_request("missing path"))?
        .to_string();
    // Version HTTP ignorée (on suppose 1.1).

    // Headers.
    let mut content_length: Option<usize> = None;
    let mut keep_alive = true; // défaut HTTP/1.1
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => return Err(HttpError::bad_request("unexpected EOF in headers")),
            Ok(_) => {}
            Err(e) if is_timeout(&e) => return Err(HttpError::request_timeout()),
            Err(e) => return Err(HttpError::bad_request(format!("read header: {e}"))),
        }
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
        } else if let Some(rest) = lower.strip_prefix("connection:") {
            if rest.trim() == "close" {
                keep_alive = false;
            }
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
        match reader.read_exact(&mut body) {
            Ok(_) => {}
            Err(e) if is_timeout(&e) => return Err(HttpError::request_timeout()),
            Err(e) => return Err(HttpError::bad_request(format!("read body: {e}"))),
        }
    }

    Ok(Some(HttpRequest {
        method,
        path,
        body,
        keep_alive,
    }))
}

/// Écrit une réponse HTTP 200 avec un corps JSON.
pub fn write_json_ok<W: Write>(
    stream: &mut W,
    body: &[u8],
    keep_alive: bool,
) -> std::io::Result<()> {
    let conn = if keep_alive { "keep-alive" } else { "close" };
    let header = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: {}\r\n\
         Access-Control-Allow-Origin: {}\r\n\
         \r\n",
        body.len(),
        conn,
        CORS_ALLOW_ORIGIN
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

/// Réponse CORS preflight (`OPTIONS`).
///
/// Retourne `204 No Content` avec les headers `Access-Control-Allow-*`.
///
/// `allow_methods` permet aux services qui exposent d'autres verbes
/// (GET pour le faucet, par ex.) de l'annoncer correctement.
pub fn write_preflight_ok<W: Write>(
    stream: &mut W,
    keep_alive: bool,
    allow_methods: &str,
) -> std::io::Result<()> {
    let conn = if keep_alive { "keep-alive" } else { "close" };
    let header = format!(
        "HTTP/1.1 204 No Content\r\n\
         Content-Length: 0\r\n\
         Connection: {}\r\n\
         Access-Control-Allow-Origin: {}\r\n\
         Access-Control-Allow-Methods: {}\r\n\
         Access-Control-Allow-Headers: {}\r\n\
         Access-Control-Max-Age: {}\r\n\
         \r\n",
        conn, CORS_ALLOW_ORIGIN, allow_methods, CORS_ALLOW_HEADERS, CORS_MAX_AGE
    );
    stream.write_all(header.as_bytes())?;
    stream.flush()
}

/// Écrit une réponse HTTP avec un statut arbitraire et un corps JSON.
///
/// Utilisé par les services (faucet, explorer) qui veulent un code HTTP
/// précis (400, 404, 429, 500, …) et un corps JSON.
pub fn write_json_status<W: Write>(
    stream: &mut W,
    status: u16,
    reason: &str,
    body: &[u8],
    keep_alive: bool,
) -> std::io::Result<()> {
    let conn = if keep_alive { "keep-alive" } else { "close" };
    let header = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: {}\r\n\
         Access-Control-Allow-Origin: {}\r\n\
         \r\n",
        status,
        reason,
        body.len(),
        conn,
        CORS_ALLOW_ORIGIN
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

/// Écrit une réponse HTTP d'erreur.
pub fn write_error<W: Write>(
    stream: &mut W,
    err: &HttpError,
    keep_alive: bool,
) -> std::io::Result<()> {
    let conn = if keep_alive { "keep-alive" } else { "close" };
    let body = format!("{}\n", err.message);
    let header = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {}\r\n\
         Connection: {}\r\n\
         Access-Control-Allow-Origin: {}\r\n\
         \r\n",
        err.status,
        err.reason,
        body.len(),
        conn,
        CORS_ALLOW_ORIGIN
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    /// Crée un serveur jetable, envoie `raw`, retourne la réponse brute.
    fn round_trip(raw: &[u8]) -> Vec<u8> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let payload = raw.to_vec();

        let client = std::thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            s.write_all(&payload).unwrap();
            s.shutdown(std::net::Shutdown::Write).unwrap();
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf);
            buf
        });

        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream);
        let req = read_request(&mut reader)
            .expect("parse ok")
            .expect("not EOF");
        // Réponse unique, fermeture explicite.
        write_json_ok(reader.get_mut(), b"{\"ok\":true}", false).unwrap();
        drop(reader);

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
        assert!(s.contains("Connection: close"));
    }

    #[test]
    fn detects_connection_close_header() {
        let raw = b"POST /rpc HTTP/1.1\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{}";
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let payload = raw.to_vec();
        let client = std::thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            s.write_all(&payload).unwrap();
            s.shutdown(std::net::Shutdown::Write).unwrap();
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf);
            buf
        });
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream);
        let req = read_request(&mut reader).unwrap().unwrap();
        assert!(
            !req.keep_alive,
            "Connection: close doit désactiver keep-alive"
        );
        write_json_ok(reader.get_mut(), b"{}", false).unwrap();
        drop(reader);
        let _ = client.join();
    }

    #[test]
    fn keep_alive_default_on_http11() {
        let raw = b"POST /rpc HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}";
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let payload = raw.to_vec();
        let client = std::thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            s.write_all(&payload).unwrap();
            s.shutdown(std::net::Shutdown::Write).unwrap();
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf);
            buf
        });
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream);
        let req = read_request(&mut reader).unwrap().unwrap();
        assert!(
            req.keep_alive,
            "HTTP/1.1 sans Connection: close → keep-alive"
        );
        write_json_ok(reader.get_mut(), b"{}", false).unwrap();
        drop(reader);
        let _ = client.join();
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

        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream);
        match read_request(&mut reader) {
            Err(e) => {
                assert_eq!(e.status, 413);
                write_error(reader.get_mut(), &e, false).unwrap();
            }
            Ok(_) => panic!("devrait rejeter"),
        }
        drop(reader);
        let _ = client.join();
    }

    #[test]
    fn eof_before_request_returns_none() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let client = std::thread::spawn(move || {
            let s = TcpStream::connect(addr).unwrap();
            // Ferme immédiatement sans rien envoyer.
            s.shutdown(std::net::Shutdown::Both).ok();
            drop(s);
        });

        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream);
        let result = read_request(&mut reader).unwrap();
        assert!(result.is_none(), "EOF propre → None");
        let _ = client.join();
    }
}
