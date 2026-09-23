//! Test d'intégration bout-en-bout : HTTP → mempool → consensus → état → HTTP.
//!
//! ## Scénario
//!
//! 1. Un nœud unique avec un validateur local.
//! 2. Alice dispose d'un compte financé (100 000 000 base units).
//! 3. On démarre un serveur RPC et un driver consensus sur le même
//!    `NodeHandle`.
//! 4. Alice envoie une transaction via HTTP (`sango_sendTransaction`) :
//!    1 000 000 base units à Carol.
//! 5. Le driver produit un bloc, inclut la transaction, applique le bloc.
//! 6. On vérifie via HTTP (`sango_getBalance`) que Carol a bien reçu.
//!
//! ## Ce que le test valide
//!
//! - Décodage de la tx depuis le hex soumis via RPC.
//! - Admission au mempool (`RpcBackend::send_transaction`).
//! - Sélection par le `Driver::maybe_propose` (candidats du mempool).
//! - Pré-validation via `Node::prepare_block_from_candidates`.
//! - Application du bloc par `Node::apply_block`.
//! - Purge du mempool après commit.
//! - Lecture de l'état final via RPC.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use sango_codec::Encode;
use sango_consensus::{LocalIdentity, Validator, ValidatorSet};
use sango_crypto::{derive_native_address, NativeKeypair};
use sango_node::{Driver, Node, NodeBackend, NodeHandle, OutgoingMessage};
use sango_primitives::{Amount, ChainId32, Epoch, NativeAddress, Signature};
use sango_rpc::RpcServer;
use sango_types::{NativeAccount, Transaction, TxKind};

// --- Constantes ------------------------------------------------------------

const CHAIN: [u8; 32] = [0x11; 32];
const ALICE_SEED: [u8; 32] = [0xA1; 32];
const VALIDATOR_SEED: [u8; 32] = [0x42; 32];

const ALICE_INITIAL: u128 = 100_000_000; // base units
const TRANSFER_AMOUNT: u128 = 1_000_000; // base units
const MAX_FEE: u128 = 1_000;
const GAS_LIMIT: u64 = 21_000;

fn chain() -> ChainId32 {
    ChainId32::from_bytes(CHAIN)
}

fn initial_supply() -> Amount {
    Amount::from_sango(1_000_000_000).unwrap()
}

// --- Helpers ---------------------------------------------------------------

fn http_post(addr: SocketAddr, body: &str) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
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

/// Fait tourner le consensus jusqu'à ce que la hauteur atteigne `target`.
///
/// ## Boucle
///
/// 1. Le driver tente de proposer (si c'est son tour).
/// 2. On draine son outbox et on réinjecte chaque message à ses propres
///    handlers (auto-loopback), jusqu'à ce qu'il n'y ait plus de message.
/// 3. On répète jusqu'à atteindre la hauteur cible.
///
/// Le validateur unique s'envoie les messages à lui-même — c'est
/// équivalent à un réseau où il est le seul participant.
fn run_until_height(driver: &mut Driver, target: u64) {
    for _ in 0..50 {
        let current = driver
            .node_handle()
            .with_node(|n| n.tip().map(|t| t.height.get()).unwrap_or(0));
        if current >= target {
            return;
        }

        driver.maybe_propose().unwrap();

        let mut safety = 0;
        loop {
            safety += 1;
            assert!(safety < 100, "consensus loop exceeded limit");

            let messages = driver.drain_outbox();
            if messages.is_empty() {
                break;
            }
            for msg in messages {
                match msg {
                    OutgoingMessage::Proposal(p) => {
                        let _ = driver.handle_proposal(*p);
                    }
                    OutgoingMessage::Prevote(v) => {
                        let _ = driver.handle_prevote(v);
                    }
                    OutgoingMessage::Precommit(c) => {
                        let _ = driver.handle_precommit(c);
                    }
                }
            }
        }
    }
    panic!("consensus did not reach height {target} within 50 iterations");
}

// --- Test ------------------------------------------------------------------

#[test]
fn alice_sends_via_rpc_and_gets_included() {
    // ---------- 1. Setup du nœud ------------------------------------------
    let dir = tempfile::tempdir().unwrap();
    let node = Node::open(dir.path(), chain(), initial_supply()).unwrap();
    let handle = NodeHandle::new(node);

    // ---------- 2. Comptes ------------------------------------------------
    let alice_kp = NativeKeypair::from_seed(ALICE_SEED);
    let alice = derive_native_address(&alice_kp.public_key());

    let validator_kp = NativeKeypair::from_seed(VALIDATOR_SEED);
    let validator = derive_native_address(&validator_kp.public_key());

    let carol = NativeAddress::from_bytes([0xCC; 20]);

    // Financer Alice (compte actif avec clé publique enregistrée).
    handle.with_node_mut(|n| {
        n.state_mut_for_test()
            .set_account(NativeAccount::from_public_key(
                alice_kp.public_key(),
                Amount::from_base_units(ALICE_INITIAL),
                0,
            ));
    });

    // ---------- 3. Validator set ------------------------------------------
    let vs = ValidatorSet::new(vec![Validator {
        address: validator,
        public_key: validator_kp.public_key(),
        voting_power: 100,
    }])
    .unwrap();

    // ---------- 4. Serveur RPC --------------------------------------------
    let backend = Arc::new(NodeBackend::new(handle.clone()));
    let server = RpcServer::bind("127.0.0.1:0".parse().unwrap(), backend).unwrap();
    let rpc_addr = server.local_addr().unwrap();
    let stop_rpc = server.shutdown_handle();
    let rpc_thread = std::thread::spawn(move || {
        let _ = server.serve();
    });

    // ---------- 5. Driver consensus ---------------------------------------
    let local = LocalIdentity::new(validator_kp.clone());
    let mut driver = Driver::new(handle.clone(), vs, Some(local), Epoch::new(0)).unwrap();

    // ---------- 6. Vérifications initiales via RPC ------------------------
    let resp = http_post(
        rpc_addr,
        r#"{"jsonrpc":"2.0","method":"sango_blockNumber","params":[],"id":1}"#,
    );
    assert!(
        extract_body(&resp).contains("\"result\":null"),
        "fresh node should have null blockNumber, got: {}",
        extract_body(&resp)
    );

    let alice_hex = alice.to_hex();
    let resp = http_post(
        rpc_addr,
        &format!(
            r#"{{"jsonrpc":"2.0","method":"sango_getBalance","params":["0x{}"],"id":2}}"#,
            alice_hex
        ),
    );
    let alice_initial_balance = extract_body(&resp);
    assert!(
        alice_initial_balance.contains(&format!("\"result\":\"{}\"", ALICE_INITIAL)),
        "alice initial balance mismatch, got: {}",
        alice_initial_balance
    );

    let carol_hex = carol.to_hex();
    let resp = http_post(
        rpc_addr,
        &format!(
            r#"{{"jsonrpc":"2.0","method":"sango_getBalance","params":["0x{}"],"id":3}}"#,
            carol_hex
        ),
    );
    assert!(
        extract_body(&resp).contains("\"result\":\"0\""),
        "carol should have 0 balance initially, got: {}",
        extract_body(&resp)
    );

    // ---------- 7. Alice envoie une tx via HTTP ---------------------------
    let tx = Transaction {
        version: sango_types::PROTOCOL_VERSION_V1,
        chain_id: chain(),
        nonce: 0,
        sender: alice,
        public_key: None, // clé déjà enregistrée
        gas_limit: GAS_LIMIT,
        max_fee: MAX_FEE,
        priority_fee: 0,
        value: Amount::from_base_units(TRANSFER_AMOUNT),
        tx_kind: TxKind::Transfer,
        recipient: Some(carol),
        data: Vec::new(),
        signature: Signature::ZERO,
    }
    .sign(&alice_kp);

    let tx_bytes = tx.encode_to_vec();
    let tx_hex = format!("0x{}", hex::encode(&tx_bytes));

    let resp = http_post(
        rpc_addr,
        &format!(
            r#"{{"jsonrpc":"2.0","method":"sango_sendTransaction","params":["{}"],"id":4}}"#,
            tx_hex
        ),
    );
    let body = extract_body(&resp);
    assert!(
        body.contains("\"result\":\"0x"),
        "sendTransaction should return a hash, got: {body}"
    );

    // ---------- 8. Consensus ----------------------------------------------
    run_until_height(&mut driver, 1);

    // ---------- 9. Vérifications finales via RPC --------------------------
    let resp = http_post(
        rpc_addr,
        r#"{"jsonrpc":"2.0","method":"sango_blockNumber","params":[],"id":5}"#,
    );
    let body = extract_body(&resp);
    assert!(
        body.contains("\"result\":1"),
        "blockNumber should be 1, got: {body}"
    );

    // Carol doit avoir reçu 1 000 000 base units.
    let resp = http_post(
        rpc_addr,
        &format!(
            r#"{{"jsonrpc":"2.0","method":"sango_getBalance","params":["0x{}"],"id":6}}"#,
            carol_hex
        ),
    );
    let body = extract_body(&resp);
    assert!(
        body.contains(&format!("\"result\":\"{}\"", TRANSFER_AMOUNT)),
        "carol should have {TRANSFER_AMOUNT}, got: {body}"
    );

    // Alice doit avoir perdu 1 000 000 + fee.
    // fee = gas_used * effective_price = 21_000 * 1 = 21_000
    // base_fee initiale = 1, priority_fee = 0 → effective = 1.
    // fee = gas_used * effective = GAS_LIMIT.
    let expected_fee: u128 = GAS_LIMIT as u128;
    let expected_alice = ALICE_INITIAL - TRANSFER_AMOUNT - expected_fee;
    let resp = http_post(
        rpc_addr,
        &format!(
            r#"{{"jsonrpc":"2.0","method":"sango_getBalance","params":["0x{}"],"id":7}}"#,
            alice_hex
        ),
    );
    let body = extract_body(&resp);
    assert!(
        body.contains(&format!("\"result\":\"{}\"", expected_alice)),
        "alice should have {expected_alice}, got: {body}"
    );

    // Validator a reçu 90 % de la fee.
    let expected_validator = expected_fee * 9 / 10;
    let validator_hex = validator.to_hex();
    let resp = http_post(
        rpc_addr,
        &format!(
            r#"{{"jsonrpc":"2.0","method":"sango_getBalance","params":["0x{}"],"id":8}}"#,
            validator_hex
        ),
    );
    let body = extract_body(&resp);
    assert!(
        body.contains(&format!("\"result\":\"{}\"", expected_validator)),
        "validator should have {expected_validator}, got: {body}"
    );

    // Le mempool doit être vide après commit.
    let pool_size = handle.with_mempool(|p| p.len());
    assert_eq!(pool_size, 0, "mempool should be empty after commit");

    // ---------- 10. Cleanup -----------------------------------------------
    stop_rpc.shutdown();
    let _ = rpc_thread.join();
}
