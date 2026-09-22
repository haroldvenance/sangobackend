//! Tests d'intégration bout-en-bout du nœud.

use sango_crypto::{derive_native_address, NativeKeypair};
use sango_exec::NATIVE_TRANSFER_GAS;
use sango_node::{Node, INITIAL_BASE_FEE};
use sango_primitives::{Amount, ChainId32, Epoch, Hash32, Height, NativeAddress, Round, Signature};
use sango_types::{Block, BlockHeader, Transaction, TxKind};

const INITIAL_SUPPLY_SANGO: u128 = 1_000_000_000;

fn chain() -> ChainId32 {
    ChainId32::from_bytes([0x11; 32])
}

fn initial_supply() -> Amount {
    Amount::from_sango(INITIAL_SUPPLY_SANGO).unwrap()
}

fn validator() -> NativeAddress {
    NativeAddress::from_bytes([0xef; 20])
}

fn recipient() -> NativeAddress {
    NativeAddress::from_bytes([0xbb; 20])
}

fn header(height: u64, previous_block_hash: Hash32, base_fee: u128) -> BlockHeader {
    BlockHeader {
        version: 1,
        chain_id: chain(),
        epoch: Epoch::new(0),
        height: Height::new(height),
        round: Round::new(0),
        previous_block_hash,
        timestamp: 1_700_000_000 + height,
        proposer_address: validator(),
        transaction_root: Hash32::ZERO,
        state_root: Hash32::ZERO,
        receipt_root: Hash32::ZERO,
        gas_used: 0,
        gas_limit: 30_000_000,
        base_fee,
    }
}

fn bootstrap_tx(kp: &NativeKeypair, nonce: u64, value: u128) -> Transaction {
    let pk = kp.public_key();
    let sender = derive_native_address(&pk);
    let tx = Transaction {
        version: 1,
        chain_id: chain(),
        nonce,
        sender,
        public_key: Some(pk),
        gas_limit: NATIVE_TRANSFER_GAS,
        max_fee: 20,
        priority_fee: 2,
        value: Amount::from_base_units(value),
        tx_kind: TxKind::Transfer,
        recipient: Some(recipient()),
        data: Vec::new(),
        signature: Signature::ZERO,
    };
    tx.sign(kp)
}

// --- Fresh node -----------------------------------------------------------

#[test]
fn fresh_node_is_empty() {
    let dir = tempfile::tempdir().unwrap();
    let node = Node::open(dir.path(), chain(), initial_supply()).unwrap();
    assert!(node.state().is_empty());
    assert_eq!(node.state().total_burned(), Amount::ZERO);
    assert_eq!(node.state().total_gas_used(), 0);
    assert!(node.tip().is_none());
    assert_eq!(node.expected_base_fee().unwrap(), INITIAL_BASE_FEE);
}

// --- Premier bloc (genesis-like) ------------------------------------------

#[test]
fn apply_first_block_ok() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::open(dir.path(), chain(), initial_supply()).unwrap();

    let block = Block {
        header: header(0, Hash32::ZERO, INITIAL_BASE_FEE),
        transactions: Vec::new(),
    };
    let r = node.apply_block(&block).unwrap();
    assert!(r.apply_result.applied.is_empty());
    assert_eq!(r.gas_used, 0);

    let tip = node.tip().unwrap();
    assert_eq!(tip.height.get(), 0);
    assert_eq!(tip.block_hash, block.hash());
    assert_eq!(tip.base_fee, INITIAL_BASE_FEE);
}

#[test]
fn first_block_wrong_parent_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::open(dir.path(), chain(), initial_supply()).unwrap();

    let block = Block {
        header: header(0, Hash32::from_bytes([0xee; 32]), INITIAL_BASE_FEE),
        transactions: Vec::new(),
    };
    let err = node.apply_block(&block).unwrap_err();
    assert!(matches!(
        err,
        sango_node::NodeError::ParentHashMismatch { .. }
    ));
}

#[test]
fn first_block_wrong_height_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::open(dir.path(), chain(), initial_supply()).unwrap();

    let block = Block {
        header: header(5, Hash32::ZERO, INITIAL_BASE_FEE),
        transactions: Vec::new(),
    };
    let err = node.apply_block(&block).unwrap_err();
    assert!(matches!(err, sango_node::NodeError::HeightMismatch { .. }));
}

#[test]
fn first_block_wrong_base_fee_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::open(dir.path(), chain(), initial_supply()).unwrap();

    let block = Block {
        header: header(0, Hash32::ZERO, 42),
        transactions: Vec::new(),
    };
    let err = node.apply_block(&block).unwrap_err();
    assert!(matches!(err, sango_node::NodeError::BaseFeeMismatch { .. }));
}

// --- Chaînage -------------------------------------------------------------

#[test]
fn apply_two_empty_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::open(dir.path(), chain(), initial_supply()).unwrap();

    let b1 = Block {
        header: header(0, Hash32::ZERO, INITIAL_BASE_FEE),
        transactions: Vec::new(),
    };
    let h1 = b1.hash();
    node.apply_block(&b1).unwrap();

    // Block 1 : gas_used = 0, target = 15M, donc base fee diminue mais
    // reste au minimum absolu (1).
    let expected_bf = node.expected_base_fee().unwrap();
    let b2 = Block {
        header: header(1, h1, expected_bf),
        transactions: Vec::new(),
    };
    node.apply_block(&b2).unwrap();

    let tip = node.tip().unwrap();
    assert_eq!(tip.height.get(), 1);
    assert_eq!(tip.block_hash, b2.hash());
}

#[test]
fn second_block_wrong_parent_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::open(dir.path(), chain(), initial_supply()).unwrap();

    let b1 = Block {
        header: header(0, Hash32::ZERO, INITIAL_BASE_FEE),
        transactions: Vec::new(),
    };
    node.apply_block(&b1).unwrap();

    let b2 = Block {
        header: header(1, Hash32::from_bytes([0xaa; 32]), INITIAL_BASE_FEE),
        transactions: Vec::new(),
    };
    let err = node.apply_block(&b2).unwrap_err();
    assert!(matches!(
        err,
        sango_node::NodeError::ParentHashMismatch { .. }
    ));
}

// --- chain_id -------------------------------------------------------------

#[test]
fn chain_id_mismatch_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::open(dir.path(), chain(), initial_supply()).unwrap();

    let mut h = header(0, Hash32::ZERO, INITIAL_BASE_FEE);
    h.chain_id = ChainId32::from_bytes([0x99; 32]);
    let block = Block {
        header: h,
        transactions: Vec::new(),
    };
    let err = node.apply_block(&block).unwrap_err();
    assert!(matches!(err, sango_node::NodeError::ChainIdMismatch));
}

// --- Transactions ---------------------------------------------------------

#[test]
fn reject_unknown_sender_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::open(dir.path(), chain(), initial_supply()).unwrap();

    let kp = NativeKeypair::from_seed([0x42; 32]);
    let tx = bootstrap_tx(&kp, 0, 100);

    let block = Block {
        header: header(0, Hash32::ZERO, INITIAL_BASE_FEE),
        transactions: vec![tx],
    };

    let err = node.apply_block(&block).unwrap_err();
    assert!(matches!(
        err,
        sango_node::NodeError::Validation { index: 0, .. }
    ));
    assert!(node.state().is_empty());
    assert!(node.tip().is_none());
}

// --- Reprise après redémarrage --------------------------------------------

#[test]
fn reopen_preserves_tip() {
    let dir = tempfile::tempdir().unwrap();

    let block_hash = {
        let mut node = Node::open(dir.path(), chain(), initial_supply()).unwrap();
        let block = Block {
            header: header(0, Hash32::ZERO, INITIAL_BASE_FEE),
            transactions: Vec::new(),
        };
        let h = block.hash();
        node.apply_block(&block).unwrap();
        h
    };

    let node = Node::open(dir.path(), chain(), initial_supply()).unwrap();
    let tip = node.tip().unwrap();
    assert_eq!(tip.height.get(), 0);
    assert_eq!(tip.block_hash, block_hash);
}

#[test]
fn state_root_is_stable_across_reopen() {
    let dir = tempfile::tempdir().unwrap();

    let root_before = {
        let mut node = Node::open(dir.path(), chain(), initial_supply()).unwrap();
        let block = Block {
            header: header(0, Hash32::ZERO, INITIAL_BASE_FEE),
            transactions: Vec::new(),
        };
        node.apply_block(&block).unwrap();
        node.state().native_state_root()
    };

    let root_after = {
        let node = Node::open(dir.path(), chain(), initial_supply()).unwrap();
        node.state().native_state_root()
    };

    assert_eq!(root_before, root_after);
}
