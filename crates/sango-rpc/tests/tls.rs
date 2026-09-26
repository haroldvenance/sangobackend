//! Tests d'intégration TLS pour le serveur RPC.
//!
//! ## Stratégie
//!
//! 1. Générer un cert self-signed pour `localhost` (via `rcgen`).
//! 2. Démarrer un `RpcServer` avec `bind_tls`.
//! 3. Se connecter en TLS depuis un client `rustls` configuré pour
//!    accepter le cert (pas de vérification CA système).
//! 4. Envoyer des requêtes JSON-RPC et vérifier les réponses.
//! 5. Vérifier que les connexions HTTP en clair sont rejetées.
//!
//! ## Note sur `StreamOwned`
//!
//! `rustls::StreamOwned` n'a **pas** de `try_clone`. On utilise donc un
//! seul `BufReader<StreamOwned<...>>` pour lire et écrire (le pattern
//! est séquentiel : write, puis read).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use sango_primitives::{Amount, ChainId32, Hash32, NativeAddress};
use sango_rpc::{RpcBackend, RpcError, RpcServer, TlsConfig};
use sango_types::{Block, NativeAccount, Transaction, ValidatorInfo};

// --- Backend minimal -------------------------------------------------------

struct TestBackend;

impl RpcBackend for TestBackend {
    fn chain_id(&self) -> ChainId32 {
        ChainId32::from_bytes([0x11; 32])
    }
    fn block_number(&self) -> Option<u64> {
        Some(99)
    }
    fn get_block_by_height(&self, _: u64) -> Option<Block> {
        None
    }
    fn get_account(&self, _: &NativeAddress) -> Option<NativeAccount> {
        None
    }
    fn get_balance(&self, _: &NativeAddress) -> Amount {
        Amount::ZERO
    }
    fn get_validators(&self) -> Vec<ValidatorInfo> {
        Vec::new()
    }
    fn send_transaction(&self, _: &Transaction) -> Result<Hash32, RpcError> {
        Err(RpcError::Internal("not used".into()))
    }
    fn eth_chain_id(&self) -> u64 {
        7777
    }
}

// --- Vérificateur de cert qui accepte tout (test uniquement) --------------

/// `ServerCertVerifier` qui accepte **tous** les certificats.
///
/// ⚠ **Inacceptable en production** — utilisé uniquement pour tester un
/// serveur avec cert self-signed sans installer la CA dans le trust store.
#[derive(Debug)]
struct AcceptAnyCert;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
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

// --- Helpers ---------------------------------------------------------------

fn spawn_tls_server() -> (std::net::SocketAddr, sango_rpc::ShutdownHandle) {
    let backend = Arc::new(TestBackend);
    let tls = TlsConfig::self_signed_localhost().expect("tls config");
    let server =
        RpcServer::bind_tls("127.0.0.1:0".parse().unwrap(), backend, tls).expect("bind_tls");
    let addr = server.local_addr().expect("local_addr");
    let shutdown = server.shutdown_handle();
    thread::spawn(move || {
        let _ = server.serve();
    });
    thread::sleep(Duration::from_millis(50));
    (addr, shutdown)
}

/// Ouvre une connexion TLS vers le serveur.
///
/// **Pas de `try_clone`** : `StreamOwned` ne le supporte pas. Le test doit
/// utiliser **un seul** `BufReader<StreamOwned<...>>` pour lire et écrire
/// (write → read → write → read → …).
fn tls_client(addr: std::net::SocketAddr) -> BufReader<StreamOwned<ClientConnection, TcpStream>> {
    let mut cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();
    cfg.enable_sni = false;

    let server_name = ServerName::try_from("localhost").unwrap();
    let conn = ClientConnection::new(Arc::new(cfg), server_name).unwrap();
    let tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let stream = StreamOwned::new(conn, tcp);
    BufReader::new(stream)
}

fn send_request(stream: &mut impl Write, body: &str, connection: Option<&str>) {
    let conn_header = match connection {
        Some(v) => format!("Connection: {v}\r\n"),
        None => String::new(),
    };
    let req = format!(
        "POST /rpc HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         {}\
         \r\n\
         {}",
        body.len(),
        conn_header,
        body
    );
    stream.write_all(req.as_bytes()).unwrap();
    stream.flush().unwrap();
}

fn read_response(reader: &mut impl BufRead) -> (String, Vec<u8>) {
    let mut headers = String::new();
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).unwrap();
        if n == 0 {
            panic!("EOF inattendu en lisant les headers");
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        headers.push_str(&line);
    }
    let cl = headers
        .lines()
        .find(|l| l.to_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; cl];
    reader.read_exact(&mut body).unwrap();
    (headers, body)
}

// --- Tests -----------------------------------------------------------------

#[test]
fn tls_two_requests_same_connection() {
    let (addr, shutdown) = spawn_tls_server();
    let mut reader = tls_client(addr);

    send_request(
        reader.get_mut(),
        r#"{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}"#,
        None,
    );
    let (h1, b1) = read_response(&mut reader);
    assert!(h1.contains("200 OK"), "headers: {h1}");
    let v1: serde_json::Value = serde_json::from_slice(&b1).unwrap();
    assert_eq!(v1["result"], "0x1e61");
    assert_eq!(v1["id"], 1);

    send_request(
        reader.get_mut(),
        r#"{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":2}"#,
        None,
    );
    let (_, b2) = read_response(&mut reader);
    let v2: serde_json::Value = serde_json::from_slice(&b2).unwrap();
    assert_eq!(v2["result"], "0x63"); // 99
    assert_eq!(v2["id"], 2);

    shutdown.shutdown();
}

#[test]
fn tls_batch_request() {
    let (addr, shutdown) = spawn_tls_server();
    let mut reader = tls_client(addr);

    let batch = r#"[
        {"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1},
        {"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":2}
    ]"#;
    send_request(reader.get_mut(), batch, None);
    let (_, b) = read_response(&mut reader);
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 2);

    shutdown.shutdown();
}

#[test]
fn tls_connection_close_terminates() {
    let (addr, shutdown) = spawn_tls_server();
    let mut reader = tls_client(addr);

    send_request(
        reader.get_mut(),
        r#"{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}"#,
        Some("close"),
    );
    let (h1, _) = read_response(&mut reader);
    assert!(h1.to_lowercase().contains("connection: close"));

    // Le serveur doit fermer → read_to_end retourne 0.
    let mut tail = Vec::new();
    let _ = reader.read_to_end(&mut tail);
    assert!(tail.is_empty(), "serveur doit avoir fermé la connexion");

    shutdown.shutdown();
}

#[test]
fn plain_http_client_to_tls_server_fails() {
    let (addr, shutdown) = spawn_tls_server();

    // Client HTTP en clair : le serveur attend un ClientHello TLS.
    // Envoyer des bytes HTTP → le handshake échouera.
    let mut tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let _ = tcp.write_all(b"GET / HTTP/1.0\r\n\r\n");
    let _ = tcp.flush();

    // Le serveur ferme la connexion (erreur TLS dans read_request).
    let mut buf = Vec::new();
    let _ = tcp.read_to_end(&mut buf);
    // On ne peut pas vérifier le contenu (le serveur peut fermer sans
    // écrire). On vérifie juste qu'il n'y a pas de réponse HTTP valide.
    let s = String::from_utf8_lossy(&buf);
    assert!(!s.contains("HTTP/1.1 200"), "devrait rejeter HTTP clair");

    shutdown.shutdown();
}
