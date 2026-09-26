//! Vérifie que le preflight CORS OPTIONS renvoie 204 avec les headers.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use sango_rpc::backend::RpcBackend;
use sango_rpc::RpcServer;

/// Backend factice minimal.
struct NoopBackend;

impl RpcBackend for NoopBackend {
    fn chain_id(&self) -> sango_primitives::ChainId32 {
        sango_primitives::ChainId32::from_bytes([0x11; 32])
    }
    fn block_number(&self) -> Option<u64> {
        None
    }
    fn get_block_by_height(&self, _: u64) -> Option<sango_types::Block> {
        None
    }
    fn get_account(
        &self,
        _: &sango_primitives::NativeAddress,
    ) -> Option<sango_types::NativeAccount> {
        None
    }
    fn get_balance(&self, _: &sango_primitives::NativeAddress) -> sango_primitives::Amount {
        sango_primitives::Amount::ZERO
    }
    fn get_validators(&self) -> Vec<sango_types::ValidatorInfo> {
        Vec::new()
    }
    fn send_transaction(
        &self,
        _: &sango_types::Transaction,
    ) -> Result<sango_primitives::Hash32, sango_rpc::RpcError> {
        Err(sango_rpc::RpcError::Internal("noop".into()))
    }
}

#[test]
fn options_preflight_returns_204_with_cors_headers() {
    let backend = Arc::new(NoopBackend);
    let server = RpcServer::bind("127.0.0.1:0".parse().unwrap(), backend).unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server.shutdown_handle();
    let join = std::thread::spawn(move || {
        let _ = server.serve();
    });

    let mut s = TcpStream::connect(addr).unwrap();
    let req = "OPTIONS /rpc HTTP/1.1\r\n\
               Host: localhost\r\n\
               Origin: http://localhost:5173\r\n\
               Access-Control-Request-Method: POST\r\n\
               Access-Control-Request-Headers: content-type\r\n\
               Content-Length: 0\r\n\
               Connection: close\r\n\
               \r\n";
    s.write_all(req.as_bytes()).unwrap();
    s.shutdown(std::net::Shutdown::Write).ok();

    let mut reader = BufReader::new(s);
    let mut status_line = String::new();
    reader.read_line(&mut status_line).unwrap();
    assert!(
        status_line.contains("204"),
        "status attendu 204, got {status_line:?}"
    );

    let mut headers = String::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        if line == "\r\n" || line == "\n" || line.is_empty() {
            break;
        }
        headers.push_str(&line.to_ascii_lowercase());
    }

    assert!(
        headers.contains("access-control-allow-origin: *"),
        "Origin manquant"
    );
    assert!(
        headers.contains("access-control-allow-methods: post, options"),
        "Methods manquant"
    );
    assert!(
        headers.contains("access-control-allow-headers: content-type, accept, authorization"),
        "Headers manquant"
    );
    assert!(
        headers.contains("access-control-max-age: 86400"),
        "Max-Age manquant"
    );

    let mut body = Vec::new();
    reader.read_to_end(&mut body).ok();
    assert!(body.is_empty(), "204 doit avoir un body vide");

    handle.shutdown();
    let _ = join.join();
}
