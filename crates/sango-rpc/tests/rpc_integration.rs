//! Tests d'intégration : serveur RPC + backend factice.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;

use sango_primitives::{Amount, ChainId32, Hash32, NativeAddress};
use sango_rpc::{RpcBackend, RpcServer};
use sango_types::{NativeAccount, Transaction, ValidatorInfo};

// --- Backend factice -------------------------------------------------------

struct FakeBackend {
    chain_id: ChainId32,
    height: u64,
    accounts: Vec<NativeAccount>,
    validators: Vec<ValidatorInfo>,
}

impl FakeBackend {
    fn new() -> Self {
        let chain_id = ChainId32::from_bytes([0x11; 32]);
        let account = NativeAccount::from_public_key(
            sango_primitives::PublicKey::from_bytes([0x42; 32]),
            Amount::from_base_units(1_000_000),
            7,
        );
        let validator = ValidatorInfo {
            address: account.address,
            public_key: account.public_key,
            self_stake: Amount::from_sango(100_000).unwrap(),
            total_delegated: Amount::from_sango(50_000).unwrap(),
            commission_bps: 700,
            pending_commission_bps: None,
            pending_commission_at: None,
            jailed: false,
            jailed_until: None,
        };
        Self {
            chain_id,
            height: 42,
            accounts: vec![account],
            validators: vec![validator],
        }
    }
}

impl RpcBackend for FakeBackend {
    fn chain_id(&self) -> ChainId32 {
        self.chain_id
    }

    fn block_number(&self) -> Option<u64> {
        Some(self.height)
    }

    fn get_block_by_height(&self, _height: u64) -> Option<sango_types::Block> {
        None
    }

    fn get_account(&self, address: &NativeAddress) -> Option<NativeAccount> {
        self.accounts
            .iter()
            .find(|a| a.address == *address)
            .copied()
    }

    fn get_balance(&self, address: &NativeAddress) -> Amount {
        self.accounts
            .iter()
            .find(|a| a.address == *address)
            .map_or(Amount::ZERO, |a| a.balance)
    }

    fn get_validators(&self) -> Vec<ValidatorInfo> {
        self.validators.clone()
    }

    fn send_transaction(&self, _tx: &Transaction) -> Result<Hash32, sango_rpc::RpcError> {
        Ok(Hash32::from_bytes([0xcd; 32]))
    }
}

// --- Helpers ---------------------------------------------------------------

fn spawn_server() -> (
    SocketAddr,
    sango_rpc::ShutdownHandle,
    std::thread::JoinHandle<()>,
) {
    let backend = Arc::new(FakeBackend::new());
    let server = RpcServer::bind("127.0.0.1:0".parse().unwrap(), backend).unwrap();
    let addr = server.local_addr().unwrap();
    let shutdown = server.shutdown_handle();
    let handle = std::thread::spawn(move || {
        let _ = server.serve();
    });
    (addr, shutdown, handle)
}

fn http_post(addr: SocketAddr, body: &str) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    let req = format!(
        "POST /rpc HTTP/1.1\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n{}",
        body.len(),
        body
    );
    stream.write_all(req.as_bytes()).unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    let mut buf = String::new();
    stream.read_to_string(&mut buf).unwrap();
    buf
}

fn extract_body(resp: &str) -> &str {
    resp.split("\r\n\r\n").nth(1).unwrap_or("")
}

// --- Tests -----------------------------------------------------------------

#[test]
fn chain_id_method() {
    let (addr, stop, h) = spawn_server();
    let resp = http_post(
        addr,
        r#"{"jsonrpc":"2.0","method":"sango_chainId","params":[],"id":1}"#,
    );
    let body = extract_body(&resp);
    assert!(body.contains("\"jsonrpc\":\"2.0\""));
    assert!(body.contains("\"id\":1"));
    // chain_id = [0x11; 32] → 0x1111... (64 chars de 1)
    assert!(body.contains("0x1111111111111111"));
    stop.shutdown();
    let _ = h.join();
}

#[test]
fn block_number_method() {
    let (addr, stop, h) = spawn_server();
    let resp = http_post(
        addr,
        r#"{"jsonrpc":"2.0","method":"sango_blockNumber","params":[],"id":2}"#,
    );
    let body = extract_body(&resp);
    assert!(body.contains("\"result\":42"));
    stop.shutdown();
    let _ = h.join();
}

#[test]
fn get_balance_returns_decimal_string() {
    let (addr, stop, h) = spawn_server();
    let account = NativeAccount::from_public_key(
        sango_primitives::PublicKey::from_bytes([0x42; 32]),
        Amount::ZERO,
        0,
    );
    let addr_hex = account.address.to_hex();
    let body = format!(
        r#"{{"jsonrpc":"2.0","method":"sango_getBalance","params":["0x{}"],"id":3}}"#,
        addr_hex
    );
    let resp = http_post(addr, &body);
    let b = extract_body(&resp);
    assert!(b.contains("\"result\":\"1000000\""), "got: {b}");
    stop.shutdown();
    let _ = h.join();
}

#[test]
fn get_account_returns_object() {
    let (addr, stop, h) = spawn_server();
    let account = NativeAccount::from_public_key(
        sango_primitives::PublicKey::from_bytes([0x42; 32]),
        Amount::ZERO,
        0,
    );
    let addr_hex = account.address.to_hex();
    let body = format!(
        r#"{{"jsonrpc":"2.0","method":"sango_getAccount","params":["0x{}"],"id":4}}"#,
        addr_hex
    );
    let resp = http_post(addr, &body);
    let b = extract_body(&resp);
    assert!(b.contains("\"balance\":\"1000000\""), "got: {b}");
    assert!(b.contains("\"nonce\":7"), "got: {b}");
    assert!(b.contains("\"publicKey\":\"0x"), "got: {b}");
    stop.shutdown();
    let _ = h.join();
}

#[test]
fn get_validators_returns_array() {
    let (addr, stop, h) = spawn_server();
    let resp = http_post(
        addr,
        r#"{"jsonrpc":"2.0","method":"sango_getValidators","params":[],"id":5}"#,
    );
    let b = extract_body(&resp);
    assert!(b.contains("\"commissionBps\":700"), "got: {b}");
    assert!(b.contains("\"jailed\":false"), "got: {b}");
    stop.shutdown();
    let _ = h.join();
}

#[test]
fn chain_info_method() {
    let (addr, stop, h) = spawn_server();
    let resp = http_post(
        addr,
        r#"{"jsonrpc":"2.0","method":"sango_chainInfo","params":[],"id":6}"#,
    );
    let b = extract_body(&resp);
    assert!(b.contains("\"height\":42"));
    assert!(b.contains("\"validatorCount\":1"));
    assert!(b.contains("\"protocolVersion\":1"));
    stop.shutdown();
    let _ = h.join();
}

#[test]
fn unknown_method_returns_error() {
    let (addr, stop, h) = spawn_server();
    let resp = http_post(
        addr,
        r#"{"jsonrpc":"2.0","method":"sango_bogus","params":[],"id":7}"#,
    );
    let b = extract_body(&resp);
    assert!(b.contains("-32601"), "got: {b}");
    assert!(b.contains("method not found"));
    stop.shutdown();
    let _ = h.join();
}

#[test]
fn bad_json_rpc_version_returns_error() {
    let (addr, stop, h) = spawn_server();
    let resp = http_post(
        addr,
        r#"{"jsonrpc":"1.0","method":"sango_chainId","params":[],"id":8}"#,
    );
    let b = extract_body(&resp);
    assert!(b.contains("-32600"), "got: {b}");
    stop.shutdown();
    let _ = h.join();
}

#[test]
fn method_not_allowed_on_get() {
    let (addr, stop, h) = spawn_server();
    let mut stream = TcpStream::connect(addr).unwrap();
    let req = "GET /rpc HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
    stream.write_all(req.as_bytes()).unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    let mut buf = String::new();
    stream.read_to_string(&mut buf).unwrap();
    assert!(buf.contains("405 Method Not Allowed"), "got: {buf}");
    stop.shutdown();
    let _ = h.join();
}
