//! Test E2E : `eth_getLogs` + `eth_getProof` sur un contrat EVM.
//!
//! ## Scénario
//!
//! 1. Un nœud avec un validateur unique.
//! 2. Alice est financée en EVM.
//! 3. On déploie un contrat dont le runtime émet un log (`LOG0`).
//! 4. On appelle le contrat (`eth_sendRawTransaction`).
//! 5. On vérifie que `eth_getLogs` retrouve le log.
//! 6. On vérifie que `eth_getProof` retourne des preuves non vides et
//!    cohérentes pour le compte Alice et un slot.

use std::sync::Arc;

use sango_consensus::{LocalIdentity, Validator, ValidatorSet};
use sango_crypto::keccak256;
use sango_node::{Driver, Node, NodeBackend, NodeHandle, OutgoingMessage};
use sango_primitives::{Amount, ChainId32, Epoch, EvmAddress, U256};
use sango_rpc::{BlockTag, EthLogFilter, RpcBackend};
use sango_types::{EvmAccount, EvmTx};

const CHAIN: [u8; 32] = [0x11; 32];
const ALICE_SEED: [u8; 32] = [0xA1; 32];
const VALIDATOR_SEED: [u8; 32] = [0x42; 32];
const EVM_CHAIN_ID: u64 = 0x53_41_4e_47_4f;

const ALICE_EVM_BALANCE: u64 = 100_000_000;

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
    let mut s = RlpStream::new_list(9);
    let nb = nonce.to_be_bytes();
    let start = nb.iter().position(|b| *b != 0).unwrap_or(8);
    s.append(&nb[start..].to_vec());
    let gpb = gas_price.to_be_bytes();
    let start = gpb.iter().position(|b| *b != 0).unwrap_or(8);
    s.append(&gpb[start..].to_vec());
    let glb = gas_limit.to_be_bytes();
    let start = glb.iter().position(|b| *b != 0).unwrap_or(8);
    s.append(&glb[start..].to_vec());
    match to {
        Some(a) => {
            let ab: &[u8] = a.as_bytes();
            s.append(&ab);
        }
        None => {
            s.append_empty_data();
        }
    }
    let vb = value.to_be_bytes::<32>();
    let start = vb.iter().position(|b| *b != 0).unwrap_or(32);
    s.append(&vb[start..].to_vec());
    s.append(&data.as_slice());
    let cb = chain_id.to_be_bytes();
    let start = cb.iter().position(|b| *b != 0).unwrap_or(8);
    s.append(&cb[start..].to_vec());
    s.append_empty_data();
    s.append_empty_data();
    let payload = s.out().to_vec();
    let prehash = keccak256(&payload);
    let (sig, recid) = sk
        .sign_prehash_recoverable(prehash.as_bytes())
        .expect("sign");
    let sb = sig.to_bytes();
    let mut r = [0u8; 32];
    let mut s2 = [0u8; 32];
    r.copy_from_slice(&sb[..32]);
    s2.copy_from_slice(&sb[32..]);
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
        s: U256::from_be_bytes::<32>(s2),
    }
}

/// Init code qui déploie `runtime` (voir revm_bridge tests).
fn init_code_for_runtime(runtime: &[u8]) -> Vec<u8> {
    let len = runtime.len() as u8;
    let preamble_len: u8 = 12;
    let mut code = Vec::with_capacity(preamble_len as usize + runtime.len());
    code.extend_from_slice(&[0x60, len]);
    code.extend_from_slice(&[0x60, preamble_len]);
    code.extend_from_slice(&[0x60, 0x00]);
    code.push(0x39);
    code.extend_from_slice(&[0x60, len]);
    code.extend_from_slice(&[0x60, 0x00]);
    code.push(0xf3);
    code.extend_from_slice(runtime);
    code
}

/// Adresse d'un contrat créé par `CREATE` (sender, nonce).
fn contract_address(sender: &EvmAddress, nonce: u64) -> EvmAddress {
    use rlp::RlpStream;
    let mut s = RlpStream::new_list(2);
    let ab: &[u8] = sender.as_bytes();
    s.append(&ab);
    let nb = nonce.to_be_bytes();
    let start = nb.iter().position(|b| *b != 0).unwrap_or(8);
    s.append(&nb[start..].to_vec());
    let h = keccak256(&s.out());
    let mut a = [0u8; 20];
    a.copy_from_slice(&h.as_bytes()[12..]);
    EvmAddress::from_bytes(a)
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
            assert!(safety < 100);
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
    panic!("consensus did not reach height {target}");
}

fn setup() -> (tempfile::TempDir, NodeHandle, Arc<NodeBackend>) {
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::open(dir.path(), chain(), initial_supply()).unwrap();

    let alice_sk = signing_key(ALICE_SEED);
    let alice = evm_address(&alice_sk);
    let mut alice_acc = EvmAccount::empty();
    alice_acc.balance = U256::from(ALICE_EVM_BALANCE);
    node.evm_mut_for_test().set_account(alice, alice_acc);
    node.persist_evm_full_for_test().unwrap();
    node.set_evm_chain_id(EVM_CHAIN_ID);

    let handle = NodeHandle::new(node);
    let backend = Arc::new(NodeBackend::new(handle.clone()));
    (dir, handle, backend)
}

fn setup_validator() -> ValidatorSet {
    let kp = sango_crypto::NativeKeypair::from_seed(VALIDATOR_SEED);
    let addr = sango_crypto::derive_native_address(&kp.public_key());
    ValidatorSet::new(vec![Validator {
        address: addr,
        public_key: kp.public_key(),
        voting_power: 100,
    }])
    .unwrap()
}

// --- Tests ----------------------------------------------------------------

#[test]
fn eth_get_logs_finds_contract_event() {
    let (_dir, handle, backend) = setup();
    let alice_sk = signing_key(ALICE_SEED);
    let alice = evm_address(&alice_sk);
    let vs = setup_validator();
    let vkp = sango_crypto::NativeKeypair::from_seed(VALIDATOR_SEED);

    // Runtime : PUSH1 0, PUSH1 0, LOG0, STOP → log vide sans topics.
    let runtime = vec![0x60, 0x00, 0x60, 0x00, 0xa0, 0x00];
    let init_code = init_code_for_runtime(&runtime);
    let contract = contract_address(&alice, 0);

    // 1. Déployer.
    let deploy = sign_legacy(
        &alice_sk,
        EVM_CHAIN_ID,
        0,
        1,
        300_000,
        None,
        U256::ZERO,
        init_code,
    );
    backend
        .eth_send_raw_transaction(&deploy.encode_ethereum_typed())
        .expect("deploy accepted");

    let local = LocalIdentity::new(vkp.clone());
    let mut driver = Driver::new(handle.clone(), vs, Some(local), Epoch::new(0)).unwrap();
    run_until_height(&mut driver, 1);

    // 2. Appeler le contrat (émet un log).
    let call = sign_legacy(
        &alice_sk,
        EVM_CHAIN_ID,
        1,
        1,
        100_000,
        Some(contract),
        U256::ZERO,
        Vec::new(),
    );
    backend
        .eth_send_raw_transaction(&call.encode_ethereum_typed())
        .expect("call accepted");
    run_until_height(&mut driver, 2);

    // 3. eth_getLogs sur [0, 2] filtré par adresse du contrat.
    let filter = EthLogFilter {
        from_block: Some(BlockTag::Number(0)),
        to_block: Some(BlockTag::Number(2)),
        block_hash: None,
        addresses: vec![contract],
        topics: vec![],
    };
    let logs = backend.eth_get_logs(&filter).expect("eth_getLogs ok");
    assert_eq!(logs.len(), 1, "expected 1 log from contract");
    assert_eq!(logs[0].address, contract);
    assert!(logs[0].topics.is_empty());
    assert!(logs[0].data.is_empty());
    assert!(!logs[0].removed);

    // 4. Filtre par adresse inexistante → 0.
    let filter_other = EthLogFilter {
        from_block: Some(BlockTag::Number(0)),
        to_block: Some(BlockTag::Number(2)),
        block_hash: None,
        addresses: vec![EvmAddress::from_bytes([0xff; 20])],
        topics: vec![],
    };
    let none = backend.eth_get_logs(&filter_other).unwrap();
    assert!(none.is_empty());

    // 5. Filtre par topic inexistant → 0.
    let filter_topic = EthLogFilter {
        from_block: Some(BlockTag::Number(0)),
        to_block: Some(BlockTag::Number(2)),
        block_hash: None,
        addresses: vec![contract],
        topics: vec![Some(vec![sango_primitives::Hash32::from_bytes([0x99; 32])])],
    };
    let none = backend.eth_get_logs(&filter_topic).unwrap();
    assert!(none.is_empty());
}

#[test]
fn eth_get_proof_returns_valid_structure() {
    let (_dir, handle, backend) = setup();
    let alice_sk = signing_key(ALICE_SEED);
    let alice = evm_address(&alice_sk);

    // Injecter un slot de storage pour Alice.
    handle.with_node_mut(|n| {
        n.evm_mut_for_test()
            .set_storage(alice, U256::from(7u64), U256::from(0xdead_u64));
    });
    handle.with_node_mut(|n| {
        n.persist_evm_full_for_test().unwrap();
    });

    // eth_getProof pour Alice + slot 7.
    let proof = backend
        .eth_get_proof(&alice, &[U256::from(7u64)], None)
        .expect("eth_getProof ok");

    assert_eq!(proof.address, alice);
    assert_eq!(proof.balance, U256::from(ALICE_EVM_BALANCE));
    assert_eq!(proof.nonce, 0);
    assert!(!proof.account_proof.is_empty(), "account_proof non-empty");
    assert_eq!(proof.storage_proof.len(), 1);
    assert_eq!(proof.storage_proof[0].key, U256::from(7u64));
    assert_eq!(proof.storage_proof[0].value, U256::from(0xdead_u64));
    assert!(
        !proof.storage_proof[0].proof.is_empty(),
        "storage proof non-empty"
    );
}

#[test]
fn eth_get_proof_missing_account_returns_absence_proof() {
    let (_dir, _handle, backend) = setup();
    let missing = EvmAddress::from_bytes([0xff; 20]);

    let proof = backend
        .eth_get_proof(&missing, &[U256::from(1u64)], None)
        .expect("eth_getProof ok");

    assert_eq!(proof.address, missing);
    assert_eq!(proof.balance, U256::ZERO);
    assert_eq!(proof.nonce, 0);
    // Preuve d'absence : MPT va jusqu'au point de divergence (au moins 1 nœud).
    assert!(!proof.account_proof.is_empty());
    assert_eq!(proof.storage_proof.len(), 1);
    assert_eq!(proof.storage_proof[0].value, U256::ZERO);
}
