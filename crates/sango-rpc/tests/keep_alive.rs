//! Tests d'intégration pour le keep-alive HTTP du serveur RPC.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use sango_primitives::{Amount, ChainId32, Hash32, NativeAddress};
use sango_rpc::{RpcBackend, RpcError, RpcServer};
use sango_types::{Block, NativeAccount, Transaction, ValidatorInfo};

// --- Backend minimal pour les tests ----------------------------------------

struct TestBackend;

impl RpcBackend for TestBackend {
    fn chain_id(&self) -> ChainId32 {
        ChainId32::from_bytes([0x11; 32])
    }
    fn block_number(&self) -> Option<u64> {
        Some(42)
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

// --- Helpers ---------------------------------------------------------------

fn spawn_server(idle: Duration, max_req: usize) -> (SocketAddr, sango_rpc::ShutdownHandle) {
    let backend = Arc::new(TestBackend);
    let server = RpcServer::bind("127.0.0.1:0".parse().unwrap(), backend)
        .expect("bind")
        .with_idle_timeout(idle)
        .with_max_requests(max_req);
    let addr = server.local_addr().expect("local_addr");
    let shutdown = server.shutdown_handle();
    thread::spawn(move || {
        let _ = server.serve();
    });
    // Délai pour que le listener soit prêt.
    thread::sleep(Duration::from_millis(50));
    (addr, shutdown)
}

fn send_request(stream: &mut TcpStream, body: &str, connection: Option<&str>) {
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

/// Lit une réponse HTTP complète (headers + body).
fn read_response(reader: &mut BufReader<TcpStream>) -> (String, Vec<u8>) {
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
fn keep_alive_two_requests_same_connection() {
    let (addr, shutdown) = spawn_server(Duration::from_secs(5), 100);

    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    // Requête 1 : eth_chainId.
    send_request(
        &mut stream,
        r#"{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}"#,
        None,
    );
    let (h1, b1) = read_response(&mut reader);
    assert!(h1.contains("200 OK"), "headers1: {h1}");
    assert!(
        h1.to_lowercase().contains("connection: keep-alive"),
        "headers1: {h1}"
    );
    let v1: serde_json::Value = serde_json::from_slice(&b1).unwrap();
    assert_eq!(v1["result"], "0x1e61"); // 7777
    assert_eq!(v1["id"], 1);

    // Requête 2 : eth_blockNumber, MÊME connexion.
    send_request(
        &mut stream,
        r#"{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":2}"#,
        None,
    );
    let (h2, b2) = read_response(&mut reader);
    assert!(h2.contains("200 OK"), "headers2: {h2}");
    let v2: serde_json::Value = serde_json::from_slice(&b2).unwrap();
    assert_eq!(v2["result"], "0x2a"); // 42
    assert_eq!(v2["id"], 2);

    shutdown.shutdown();
}

#[test]
fn connection_close_header_terminates_connection() {
    let (addr, shutdown) = spawn_server(Duration::from_secs(5), 100);

    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    send_request(
        &mut stream,
        r#"{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}"#,
        Some("close"),
    );
    let (h1, _) = read_response(&mut reader);
    assert!(
        h1.to_lowercase().contains("connection: close"),
        "headers: {h1}"
    );

    // Le serveur doit fermer la connexion → lecture suivante → 0 byte.
    let mut tail = Vec::new();
    let _ = reader.read_to_end(&mut tail);
    assert!(tail.is_empty(), "serveur doit avoir fermé la connexion");

    shutdown.shutdown();
}

#[test]
fn max_requests_per_connection_forces_close() {
    let (addr, shutdown) = spawn_server(Duration::from_secs(5), 2);

    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    // Req 1 : keep-alive (served=1 < max=2).
    send_request(
        &mut stream,
        r#"{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}"#,
        None,
    );
    let (h1, _) = read_response(&mut reader);
    assert!(h1.to_lowercase().contains("connection: keep-alive"));

    // Req 2 : max atteint → Connection: close.
    send_request(
        &mut stream,
        r#"{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":2}"#,
        None,
    );
    let (h2, _) = read_response(&mut reader);
    assert!(
        h2.to_lowercase().contains("connection: close"),
        "la 2e requête doit fermer (max=2) : {h2}"
    );

    // Connexion fermée.
    let mut tail = Vec::new();
    let _ = reader.read_to_end(&mut tail);
    assert!(tail.is_empty());

    shutdown.shutdown();
}

#[test]
fn idle_timeout_closes_silently() {
    let (addr, shutdown) = spawn_server(Duration::from_millis(200), 100);

    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    // Requête rapide pour valider que la connexion est ouverte.
    send_request(
        &mut stream,
        r#"{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}"#,
        None,
    );
    let (_, _) = read_response(&mut reader);

    // Attente supérieure à idle_timeout sans envoyer de requête.
    thread::sleep(Duration::from_millis(500));

    // Le serveur a dû fermer la connexion → read_to_end termine avec 0.
    let mut tail = Vec::new();
    let _ = reader.read_to_end(&mut tail);
    assert!(
        tail.is_empty(),
        "serveur doit avoir fermé après idle_timeout"
    );

    shutdown.shutdown();
}

#[test]
fn batch_and_keep_alive_combine() {
    let (addr, shutdown) = spawn_server(Duration::from_secs(5), 100);

    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    // Requête 1 : batch de 2 items.
    let batch = r#"[
        {"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1},
        {"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":2}
    ]"#;
    send_request(&mut stream, batch, None);
    let (_, b1) = read_response(&mut reader);
    let v1: serde_json::Value = serde_json::from_slice(&b1).unwrap();
    assert_eq!(v1.as_array().unwrap().len(), 2);

    // Requête 2 : single, même connexion.
    send_request(
        &mut stream,
        r#"{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":3}"#,
        None,
    );
    let (_, b2) = read_response(&mut reader);
    let v2: serde_json::Value = serde_json::from_slice(&b2).unwrap();
    assert_eq!(v2["id"], 3);

    shutdown.shutdown();
}
