//! Client JSON-RPC minimal pour parler à un nœud Sango.
//!
//! Transport HTTP/1.1 `POST /rpc`, synchrone. Supporte :
//!
//! - **HTTP clair** (défaut) : `RpcClient::new(endpoint)`.
//! - **HTTPS/TLS** : `RpcClient::new_with_tls(endpoint, opts)`.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rustls::crypto::{ring as rustls_ring, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde_json::{json, Value};

use crate::error::WalletError;

/// Installe **une seule fois** le provider rustls (`ring`).
fn init_tls_crypto() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        let _ = CryptoProvider::install_default(rustls_ring::default_provider());
    });
}

/// Mode de confiance TLS côté client.
#[derive(Clone, Debug)]
pub enum TrustMode {
    /// CAs système (webpki-roots).
    SystemCAs,
    /// CA custom fournie en DER (bytes).
    CustomCa(Vec<u8>),
    /// Accepte **tout** certificat (devnet uniquement, ⚠ dangereux).
    AcceptAny,
}

/// Options TLS côté client.
#[derive(Clone, Debug)]
pub struct TlsClientOptions {
    /// Mode de confiance.
    pub trust: TrustMode,
    /// Nom du serveur pour SNI (défaut : "localhost").
    pub server_name: String,
}

/// Client RPC.
#[derive(Debug, Clone)]
pub struct RpcClient {
    endpoint: String, // "host:port"
    timeout: Duration,
    tls: Option<Arc<TlsInner>>,
}

#[derive(Debug)]
struct TlsInner {
    config: Arc<ClientConfig>,
    server_name: String,
}

impl RpcClient {
    /// Client HTTP clair. Accepte `http://host:port` ou `host:port`.
    pub fn new(endpoint: &str) -> Self {
        let endpoint = endpoint
            .strip_prefix("http://")
            .or_else(|| endpoint.strip_prefix("https://"))
            .unwrap_or(endpoint)
            .to_string();
        Self {
            endpoint,
            timeout: Duration::from_secs(10),
            tls: None,
        }
    }

    /// Client HTTPS/TLS. Accepte `https://host:port` ou `host:port`.
    pub fn new_with_tls(endpoint: &str, opts: TlsClientOptions) -> Result<Self, WalletError> {
        init_tls_crypto();

        let endpoint = endpoint
            .strip_prefix("http://")
            .or_else(|| endpoint.strip_prefix("https://"))
            .unwrap_or(endpoint)
            .to_string();

        let config = build_client_config(&opts.trust)?;
        Ok(Self {
            endpoint,
            timeout: Duration::from_secs(10),
            tls: Some(Arc::new(TlsInner {
                config: Arc::new(config),
                server_name: opts.server_name,
            })),
        })
    }

    /// Appelle une méthode RPC et retourne le champ `result`.
    pub fn call(&self, method: &str, params: Value) -> Result<Value, WalletError> {
        let id = 1u64;
        let request = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": id,
        });
        let body = serde_json::to_vec(&request)?;
        let response_body = self.http_post(&body)?;

        let response: Value = serde_json::from_slice(&response_body)?;
        if let Some(err) = response.get("error") {
            let code = err.get("code").and_then(Value::as_i64).unwrap_or(-1) as i32;
            let message = err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            return Err(WalletError::RpcResponse { code, message });
        }
        response
            .get("result")
            .cloned()
            .ok_or_else(|| WalletError::Rpc("missing result".into()))
    }

    fn http_post(&self, body: &[u8]) -> Result<Vec<u8>, WalletError> {
        let addr = self
            .endpoint
            .to_socket_addrs()
            .map_err(|e| WalletError::Rpc(format!("bad endpoint {}: {e}", self.endpoint)))?
            .next()
            .ok_or_else(|| WalletError::Rpc(format!("cannot resolve {}", self.endpoint)))?;

        let tcp = TcpStream::connect_timeout(&addr, self.timeout)
            .map_err(|e| WalletError::Rpc(format!("connect: {e}")))?;
        tcp.set_read_timeout(Some(self.timeout)).ok();
        tcp.set_write_timeout(Some(self.timeout)).ok();

        match &self.tls {
            None => http_post_plain(tcp, body, &self.endpoint),
            Some(tls) => http_post_tls(tcp, body, &self.endpoint, tls),
        }
    }
}

// --- Implémentations par transport -----------------------------------------

fn http_post_plain(mut tcp: TcpStream, body: &[u8], host: &str) -> Result<Vec<u8>, WalletError> {
    let header = format!(
        "POST /rpc HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        host,
        body.len()
    );
    tcp.write_all(header.as_bytes())
        .map_err(|e| WalletError::Rpc(format!("write header: {e}")))?;
    tcp.write_all(body)
        .map_err(|e| WalletError::Rpc(format!("write body: {e}")))?;
    tcp.shutdown(std::net::Shutdown::Write)
        .map_err(|e| WalletError::Rpc(format!("shutdown: {e}")))?;

    read_http_response(&mut tcp)
}

fn http_post_tls(
    tcp: TcpStream,
    body: &[u8],
    host: &str,
    tls: &TlsInner,
) -> Result<Vec<u8>, WalletError> {
    let server_name = ServerName::try_from(tls.server_name.clone())
        .map_err(|e| WalletError::Rpc(format!("bad server name: {e}")))?;
    let conn = ClientConnection::new(tls.config.clone(), server_name)
        .map_err(|e| WalletError::Rpc(format!("tls client conn: {e}")))?;
    let mut stream = StreamOwned::new(conn, tcp);

    let header = format!(
        "POST /rpc HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        host,
        body.len()
    );
    stream
        .write_all(header.as_bytes())
        .map_err(|e| WalletError::Rpc(format!("tls write header: {e}")))?;
    stream
        .write_all(body)
        .map_err(|e| WalletError::Rpc(format!("tls write body: {e}")))?;
    stream
        .flush()
        .map_err(|e| WalletError::Rpc(format!("tls flush: {e}")))?;

    read_http_response(&mut stream)
}

/// Lit une réponse HTTP complète depuis `stream`, en se basant sur
/// `Content-Length` (pas sur `close_notify`).
///
/// ## Pourquoi pas `read_to_end`
///
/// Notre serveur ferme la connexion sans `close_notify` TLS, ce qui fait
/// échouer `read_to_end` côté client (`peer closed connection without
/// sending TLS close_notify`). On lit donc **exactement** `Content-Length`
/// octets après les headers.
fn read_http_response<S: Read>(stream: &mut S) -> Result<Vec<u8>, WalletError> {
    let mut reader = BufReader::new(stream);

    // Statut HTTP.
    let mut status = String::new();
    reader
        .read_line(&mut status)
        .map_err(|e| WalletError::Rpc(format!("read status: {e}")))?;
    if !status.starts_with("HTTP/1.1 200") {
        return Err(WalletError::Rpc(format!(
            "unexpected status: {}",
            status.trim_end()
        )));
    }

    // Headers : chercher Content-Length.
    let mut content_length: Option<usize> = None;
    loop {
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .map_err(|e| WalletError::Rpc(format!("read header: {e}")))?;
        if n == 0 {
            return Err(WalletError::Rpc("eof in headers".into()));
        }
        if line.trim().is_empty() {
            break;
        }
        let lower = line.to_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            content_length = v.trim().parse().ok();
        }
    }

    let len =
        content_length.ok_or_else(|| WalletError::Rpc("missing content-length header".into()))?;
    let mut body = vec![0u8; len];
    reader
        .read_exact(&mut body)
        .map_err(|e| WalletError::Rpc(format!("read body: {e}")))?;
    Ok(body)
}

/// Retourne l'index du premier byte du corps HTTP (après `\r\n\r\n`).
#[allow(dead_code)]
fn body_offset(bytes: &[u8]) -> Option<usize> {
    for i in 0..bytes.len().saturating_sub(3) {
        if &bytes[i..i + 4] == b"\r\n\r\n" {
            return Some(i + 4);
        }
    }
    None
}

// --- TLS config ------------------------------------------------------------

fn build_client_config(trust: &TrustMode) -> Result<ClientConfig, WalletError> {
    match trust {
        TrustMode::SystemCAs => {
            let mut root_store = RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            Ok(ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth())
        }
        TrustMode::CustomCa(der_bytes) => {
            let mut root_store = RootCertStore::empty();
            let cert = CertificateDer::from(der_bytes.clone());
            root_store
                .add(cert)
                .map_err(|e| WalletError::Rpc(format!("bad CA: {e}")))?;
            Ok(ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth())
        }
        TrustMode::AcceptAny => {
            let config = ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
                .with_no_client_auth();
            Ok(config)
        }
    }
}

/// Vérificateur qui accepte **tout** certificat (devnet uniquement).
#[derive(Debug)]
struct AcceptAnyCert;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme::*;
        vec![
            RSA_PKCS1_SHA256,
            RSA_PKCS1_SHA384,
            RSA_PKCS1_SHA512,
            ECDSA_NISTP256_SHA256,
            ECDSA_NISTP384_SHA384,
            RSA_PSS_SHA256,
            RSA_PSS_SHA384,
            RSA_PSS_SHA512,
            ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_offset_basic() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody";
        let offset = body_offset(resp).unwrap();
        assert_eq!(&resp[offset..], b"body");
        assert_eq!(offset, 38);
    }

    #[test]
    fn body_offset_missing() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n";
        assert!(body_offset(resp).is_none());
    }

    #[test]
    fn endpoint_strips_http_prefix() {
        let c = RpcClient::new("http://127.0.0.1:8080");
        assert_eq!(c.endpoint, "127.0.0.1:8080");
    }

    #[test]
    fn endpoint_strips_https_prefix_for_tls() {
        init_tls_crypto();
        let c = RpcClient::new_with_tls(
            "https://127.0.0.1:8080",
            TlsClientOptions {
                trust: TrustMode::AcceptAny,
                server_name: "localhost".into(),
            },
        )
        .unwrap();
        assert_eq!(c.endpoint, "127.0.0.1:8080");
        assert!(c.tls.is_some());
    }
}
