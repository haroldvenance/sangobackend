//! Client JSON-RPC minimal pour parler à un nœud Sango.
//!
//! Transport HTTP/1.1 `POST /rpc`, synchrone, sans TLS (V1).

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use serde_json::{json, Value};

use crate::error::WalletError;

/// Client RPC.
#[derive(Debug, Clone)]
pub struct RpcClient {
    endpoint: String, // "host:port"
    timeout: Duration,
}

impl RpcClient {
    /// Crée un client à partir d'un endpoint `host:port` ou `http://host:port`.
    pub fn new(endpoint: &str) -> Self {
        let endpoint = endpoint
            .strip_prefix("http://")
            .unwrap_or(endpoint)
            .to_string();
        Self {
            endpoint,
            timeout: Duration::from_secs(10),
        }
    }

    /// Appelle une méthode RPC et retourne le champ `result`.
    ///
    /// # Erreurs
    ///
    /// - [`WalletError::Rpc`] pour les erreurs de transport.
    /// - [`WalletError::RpcResponse`] si le nœud retourne une erreur JSON-RPC.
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

        let mut stream = TcpStream::connect_timeout(&addr, self.timeout)
            .map_err(|e| WalletError::Rpc(format!("connect: {e}")))?;
        stream.set_read_timeout(Some(self.timeout)).ok();
        stream.set_write_timeout(Some(self.timeout)).ok();

        let header = format!(
            "POST /rpc HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n",
            self.endpoint,
            body.len()
        );
        stream
            .write_all(header.as_bytes())
            .map_err(|e| WalletError::Rpc(format!("write header: {e}")))?;
        stream
            .write_all(body)
            .map_err(|e| WalletError::Rpc(format!("write body: {e}")))?;
        stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(|e| WalletError::Rpc(format!("shutdown: {e}")))?;

        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .map_err(|e| WalletError::Rpc(format!("read response: {e}")))?;

        // Trouver le début du corps.
        let body_start = body_offset(&response)
            .ok_or_else(|| WalletError::Rpc("malformed response: no header end".into()))?;
        let headers = &response[..body_start];

        // Vérifier le statut.
        let header_str = String::from_utf8_lossy(headers);
        if !header_str.starts_with("HTTP/1.1 200") {
            return Err(WalletError::Rpc(format!(
                "unexpected status: {}",
                header_str.lines().next().unwrap_or("")
            )));
        }
        Ok(response[body_start..].to_vec())
    }
}

/// Retourne l'index du premier byte du corps HTTP (après `\r\n\r\n`).
fn body_offset(bytes: &[u8]) -> Option<usize> {
    for i in 0..bytes.len().saturating_sub(3) {
        if &bytes[i..i + 4] == b"\r\n\r\n" {
            return Some(i + 4);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_offset_basic() {
        // Décompte :
        //   "HTTP/1.1 200 OK"          15 bytes  (0..15)
        //   "\r\n"                      2 bytes  (15..17)
        //   "Content-Length: 4"        17 bytes  (17..34)
        //   "\r\n"                      2 bytes  (34..36)
        //   "\r\n"                      2 bytes  (36..38)
        //   "body"                                (38..42)
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
}
