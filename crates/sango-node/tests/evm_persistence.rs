//! Test d'intégration : persistance de l'état EVM dans RocksDB.
//!
//! ## Scénario
//!
//! 1. Ouvrir un nœud vierge.
//! 2. Manipuler directement `EvmState` (comptes, storage, code).
//! 3. Persister l'état via `persist_evm_full_for_test`.
//! 4. Rouvrir le nœud.
//! 5. Vérifier que `state_root` et tous les champs sont identiques.

use sango_crypto::keccak256;
use sango_node::Node;
use sango_primitives::{Amount, ChainId32, EvmAddress, U256};
use sango_types::EvmAccount;

const CHAIN: [u8; 32] = [0x11; 32];

fn chain() -> ChainId32 {
    ChainId32::from_bytes(CHAIN)
}

fn supply() -> Amount {
    Amount::from_sango(1_000_000_000).unwrap()
}

fn addr(b: u8) -> EvmAddress {
    EvmAddress::from_bytes([b; 20])
}

fn account(nonce: u64, balance: u64) -> EvmAccount {
    let mut a = EvmAccount::empty();
    a.nonce = nonce;
    a.balance = U256::from(balance);
    a
}

#[test]
fn empty_evm_state_after_fresh_open() {
    let dir = tempfile::tempdir().unwrap();
    let node = Node::open(dir.path(), chain(), supply()).unwrap();
    assert!(node.evm().is_empty());
    // `EvmState::state_root()` retourne `Keccak256(RLP(""))` quand vide.
    // On l'obtient via `EvmAccount::empty().storage_root` (même constante).
    let empty_storage_root = sango_types::EvmAccount::empty().storage_root;
    assert_eq!(
        node.evm().state_root(),
        empty_storage_root,
        "EvmState vide → MPT vide"
    );
}

#[test]
fn evm_account_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();

    let expected_root;
    {
        let mut node = Node::open(dir.path(), chain(), supply()).unwrap();
        node.evm_mut_for_test()
            .set_account(addr(0xaa), account(5, 1000));
        expected_root = node.evm().state_root();
        node.persist_evm_full_for_test().unwrap();
    }

    let node = Node::open(dir.path(), chain(), supply()).unwrap();
    assert_eq!(node.evm().state_root(), expected_root);
    let acc = node.evm().get_account(&addr(0xaa)).unwrap();
    assert_eq!(acc.nonce, 5);
    assert_eq!(acc.balance, U256::from(1000u64));
}

#[test]
fn evm_storage_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();

    let expected_root;
    {
        let mut node = Node::open(dir.path(), chain(), supply()).unwrap();
        node.evm_mut_for_test()
            .set_storage(addr(0xaa), U256::from(1u64), U256::from(42u64));
        node.evm_mut_for_test()
            .set_storage(addr(0xaa), U256::from(7u64), U256::from(999u64));
        expected_root = node.evm().state_root();
        node.persist_evm_full_for_test().unwrap();
    }

    let node = Node::open(dir.path(), chain(), supply()).unwrap();
    assert_eq!(node.evm().state_root(), expected_root);
    assert_eq!(
        node.evm().get_storage(&addr(0xaa), U256::from(1u64)),
        U256::from(42u64)
    );
    assert_eq!(
        node.evm().get_storage(&addr(0xaa), U256::from(7u64)),
        U256::from(999u64)
    );
}

#[test]
fn evm_code_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();

    let code = vec![0x60, 0x01, 0x60, 0x02];
    let code_hash = keccak256(&code);

    let expected_root;
    {
        let mut node = Node::open(dir.path(), chain(), supply()).unwrap();
        let mut acc = account(0, 0);
        acc.code_hash = code_hash;
        node.evm_mut_for_test().set_account(addr(0xaa), acc);
        node.evm_mut_for_test()
            .put_code(code_hash, code.clone())
            .unwrap();
        expected_root = node.evm().state_root();
        node.persist_evm_full_for_test().unwrap();
    }

    let node = Node::open(dir.path(), chain(), supply()).unwrap();
    assert_eq!(node.evm().state_root(), expected_root);
    let acc = node.evm().get_account(&addr(0xaa)).unwrap();
    assert_eq!(acc.code_hash, code_hash);
    let loaded = node.evm().get_code(&code_hash).unwrap();
    assert_eq!(loaded, code.as_slice());
}

#[test]
fn complete_evm_state_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();

    let code = vec![0x60, 0x42];
    let code_hash = keccak256(&code);

    let expected_root;
    {
        let mut node = Node::open(dir.path(), chain(), supply()).unwrap();

        // Compte 1 : EOA simple
        node.evm_mut_for_test()
            .set_account(addr(0x01), account(3, 5_000));

        // Compte 2 : contrat avec code + storage
        let mut contract = account(0, 0);
        contract.code_hash = code_hash;
        node.evm_mut_for_test().set_account(addr(0x02), contract);
        node.evm_mut_for_test()
            .put_code(code_hash, code.clone())
            .unwrap();
        node.evm_mut_for_test()
            .set_storage(addr(0x02), U256::from(1u64), U256::from(0xdead_u64));
        node.evm_mut_for_test()
            .set_storage(addr(0x02), U256::from(2u64), U256::from(0xbeef_u64));

        expected_root = node.evm().state_root();
        node.persist_evm_full_for_test().unwrap();
    }

    let node = Node::open(dir.path(), chain(), supply()).unwrap();
    assert_eq!(node.evm().state_root(), expected_root);

    // Compte 1
    let a1 = node.evm().get_account(&addr(0x01)).unwrap();
    assert_eq!(a1.nonce, 3);
    assert_eq!(a1.balance, U256::from(5_000u64));

    // Compte 2
    let a2 = node.evm().get_account(&addr(0x02)).unwrap();
    assert_eq!(a2.code_hash, code_hash);
    assert_eq!(node.evm().get_code(&code_hash).unwrap(), code.as_slice());
    assert_eq!(
        node.evm().get_storage(&addr(0x02), U256::from(1u64)),
        U256::from(0xdead_u64)
    );
    assert_eq!(
        node.evm().get_storage(&addr(0x02), U256::from(2u64)),
        U256::from(0xbeef_u64)
    );
}
