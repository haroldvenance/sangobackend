//! Test E2E : EVM tx via mempool → bloc → exécution → état.
//!
//! ## Scénario
//!
//! 1. Un nœud avec un validateur unique.
//! 2. Alice dispose d'un compte EVM (financé), persisté via
//!    `persist_evm_full_for_test`.
//! 3. On démarre un driver consensus.
//! 4. Alice signe une tx Legacy (transfert vers Bob) et la soumet via
//!    `NodeBackend::eth_send_raw_transaction`.
//! 5. Le driver produit un bloc, l'inclut, l'exécute.
//! 6. On vérifie le solde de Bob, le nonce d'Alice, et la purge du
//!    mempool EVM.

use std::sync::Arc;

use sango_consensus::{LocalIdentity, Validator, ValidatorSet};
use sango_crypto::keccak256;
use sango_node::{Driver, Node, NodeBackend, NodeHandle, OutgoingMessage};
use sango_primitives::{Amount, ChainId32, Epoch, EvmAddress, Hash32, U256};
use sango_rpc::RpcBackend;
use sango_types::{EvmAccount, EvmTx};

const CHAIN: [u8; 32] = [0x11; 32];
const ALICE_SEED: [u8; 32] = [0xA1; 32];
const VALIDATOR_SEED: [u8; 32] = [0x42; 32];
const EVM_CHAIN_ID: u64 = 0x53_41_4e_47_4f; // "SANGO" ASCII

const ALICE_EVM_BALANCE: u64 = 1_000_000;

fn chain() -> ChainId32 {
    ChainId32::from_bytes(CHAIN)
}

fn initial_supply() -> Amount {
    Amount::from_sango(1_000_000_000).unwrap()
}

fn signing_key(seed: [u8; 32]) -> k256::ecdsa::SigningKey {
    k256::ecdsa::SigningKey::from_bytes((&seed).into()).expect("valid scalar")
}

fn evm_address(sk: &k256::ecdsa::SigningKey) -> EvmAddress {
    let vk = sk.verifying_key();
    let point = vk.to_encoded_point(false);
    let h = keccak256(&point.as_bytes()[1..]);
    let mut a = [0u8; 20];
    a.copy_from_slice(&h.as_bytes()[12..]);
    EvmAddress::from_bytes(a)
}

/// Signe une Legacy tx (EIP-155).
///
/// Paramètres nombreux (8) : on tolère pour rester lisible en test.
#[allow(clippy::too_many_arguments)]
fn sign_legacy(
    sk: &k256::ecdsa::SigningKey,
    chain_id: u64,
    nonce: u64,
    gas_price: u64,
    gas_limit: u64,
    to: Option<EvmAddress>,
    value: U256,
    data: Vec<u8>,
) -> EvmTx {
    use rlp::RlpStream;

    // (1) signing payload = RLP([nonce, gas_price, gas_limit, to, value, data, chain_id, 0, 0])
    let mut s = RlpStream::new_list(9);
    // nonce (minimal BE)
    let nb = nonce.to_be_bytes();
    let start = nb.iter().position(|b| *b != 0).unwrap_or(8);
    s.append(&nb[start..].to_vec());
    // gas_price
    let gpb = gas_price.to_be_bytes();
    let start = gpb.iter().position(|b| *b != 0).unwrap_or(8);
    s.append(&gpb[start..].to_vec());
    // gas_limit
    let glb = gas_limit.to_be_bytes();
    let start = glb.iter().position(|b| *b != 0).unwrap_or(8);
    s.append(&glb[start..].to_vec());
    // to
    match to {
        Some(a) => {
            let ab: &[u8] = a.as_bytes();
            s.append(&ab);
        }
        None => {
            s.append_empty_data();
        }
    }
    // value
    let vb = value.to_be_bytes::<32>();
    let start = vb.iter().position(|b| *b != 0).unwrap_or(32);
    s.append(&vb[start..].to_vec());
    // data
    s.append(&data.as_slice());
    // chain_id
    let cb = chain_id.to_be_bytes();
    let start = cb.iter().position(|b| *b != 0).unwrap_or(8);
    s.append(&cb[start..].to_vec());
    s.append_empty_data();
    s.append_empty_data();
    let payload = s.out().to_vec();
    let prehash = keccak256(&payload);

    // (2) Sign
    let (sig, recid) = sk
        .sign_prehash_recoverable(prehash.as_bytes())
        .expect("sign");
    let sig_bytes = sig.to_bytes();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig_bytes[..32]);
    s.copy_from_slice(&sig_bytes[32..]);

    EvmTx::Legacy {
        chain_id,
        nonce,
        gas_price: U256::from(gas_price),
        gas_limit,
        to,
        value,
        data,
        y_parity: recid.to_byte(),
        r: U256::from_be_bytes::<32>(r),
        s: U256::from_be_bytes::<32>(s),
    }
}

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

#[test]
fn evm_transfer_via_raw_tx_gets_included() {
    // --- Setup nœud ---
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::open(dir.path(), chain(), initial_supply()).unwrap();

    let alice_sk = signing_key(ALICE_SEED);
    let alice = evm_address(&alice_sk);
    let bob = EvmAddress::from_bytes([0xBB; 20]);

    // Financer Alice en EVM (persisté).
    let mut alice_acc = EvmAccount::empty();
    alice_acc.balance = U256::from(ALICE_EVM_BALANCE);
    node.evm_mut_for_test().set_account(alice, alice_acc);
    node.persist_evm_full_for_test().unwrap();

    // Chain ID EVM natif du nœud.
    node.set_evm_chain_id(EVM_CHAIN_ID);

    // --- Setup validator ---
    let validator_kp = sango_crypto::NativeKeypair::from_seed(VALIDATOR_SEED);
    let validator_addr = sango_crypto::derive_native_address(&validator_kp.public_key());
    let vs = ValidatorSet::new(vec![Validator {
        address: validator_addr,
        public_key: validator_kp.public_key(),
        voting_power: 100,
    }])
    .unwrap();

    let handle = NodeHandle::new(node);
    let backend = Arc::new(NodeBackend::new(handle.clone()));

    // --- Soumettre la tx EVM via RPC ---
    let bob_balance_before = handle.with_node(|n| n.evm_get_balance(&bob));
    assert_eq!(bob_balance_before, U256::ZERO);

    let tx = sign_legacy(
        &alice_sk,
        EVM_CHAIN_ID,
        0,
        1, // gas_price = 1 (base fee initiale)
        21_000,
        Some(bob),
        U256::from(1_000u64),
        Vec::new(),
    );
    let raw = tx.encode_ethereum_typed();

    let tx_hash = backend
        .eth_send_raw_transaction(&raw)
        .expect("eth_sendRawTransaction should accept the tx");

    // Le mempool EVM contient la tx.
    assert_eq!(handle.with_evm_mempool(|p| p.len()), 1);
    assert!(handle.with_evm_mempool(|p| p.contains(&tx_hash)));

    // --- Consensus ---
    let local = LocalIdentity::new(validator_kp);
    let mut driver = Driver::new(handle.clone(), vs, Some(local), Epoch::new(0)).unwrap();
    run_until_height(&mut driver, 1);

    // --- Vérifications ---
    // Bob a reçu 1000.
    let bob_balance_after = handle.with_node(|n| n.evm_get_balance(&bob));
    assert_eq!(bob_balance_after, U256::from(1_000u64));

    // Alice a été débitée de 1000 + gas (21000 * 1).
    let expected_alice = ALICE_EVM_BALANCE as u128 - 1_000 - 21_000;
    let alice_after = handle.with_node(|n| n.evm_get_balance(&alice));
    assert_eq!(alice_after, U256::from(expected_alice as u64));

    // Nonce d'Alice = 1.
    let alice_nonce = handle.with_node(|n| n.evm_get_nonce(&alice));
    assert_eq!(alice_nonce, 1);

    // Mempool EVM purgé.
    assert_eq!(handle.with_evm_mempool(|p| p.len()), 0);

    // Persistance : rouvrir le node → mêmes soldes.
    drop(driver);
    drop(backend);
    drop(handle);
    let node2 = Node::open(dir.path(), chain(), initial_supply()).unwrap();
    assert_eq!(node2.evm_get_balance(&bob), U256::from(1_000u64));
    assert_eq!(
        node2.evm_get_balance(&alice),
        U256::from(expected_alice as u64)
    );
    assert_eq!(node2.evm_get_nonce(&alice), 1);

    // Marqueur anti-warning.
    let _ = Hash32::ZERO;
}
