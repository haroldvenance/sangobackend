//! Tests d'intégration bout-en-bout du nœud.

use sango_crypto::{derive_native_address, NativeKeypair};
use sango_exec::NATIVE_TRANSFER_GAS;
use sango_node::{Node, INITIAL_BASE_FEE};
use sango_primitives::{Amount, ChainId32, Epoch, Hash32, Height, NativeAddress, Round, Signature};
use sango_types::{Block, BlockHeader, LogsBloom, Receipt, ReceiptStatus, Transaction, Tx, TxKind};

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

/// Construit un bloc **valide** via le nœud lui-même.
///
/// Utilise `Node::prepare_block_from_candidates` — le même chemin que le
/// proposeur en production — donc les roots (`transaction_root`,
/// `receipt_root`, `state_root`) sont calculées correctement.
fn build_block(node: &Node, candidates: Vec<Transaction>) -> Block {
    // 4c.3.7 : `prepare_block_from_candidates` prend désormais `Vec<Tx>`.
    let candidates: Vec<Tx> = candidates.into_iter().map(Tx::Native).collect();
    let (_, height) = match node.tip() {
        Some(t) => (t.block_hash, t.height.get() + 1),
        None => (Hash32::ZERO, 0),
    };
    let timestamp = 1_700_000_000 + height;
    let (block, _validated) = node.prepare_block_from_candidates(
        Epoch::new(0),
        Round::new(0),
        candidates,
        1024,
        validator(),
        timestamp,
        Vec::new(),
    );
    block
}

/// Construit les receipts **attendus** pour une séquence de `TX_TRANSFER`
/// valides. Utilisé pour calculer un `receipt_root` cohérent dans les
/// tests qui échouent **avant** la vérification du `state_root`.
fn expected_receipts_for_transfers(txs: &[Transaction]) -> Vec<Receipt> {
    let mut out = Vec::with_capacity(txs.len());
    let mut cumulative: u64 = 0;
    for tx in txs {
        cumulative += NATIVE_TRANSFER_GAS;
        out.push(Receipt {
            tx_hash: tx.hash(),
            status: ReceiptStatus::Success,
            cumulative_gas_used: cumulative,
            gas_used: NATIVE_TRANSFER_GAS,
            contract_address: None,
            logs_bloom: LogsBloom::EMPTY,
            logs: Vec::new(),
        });
    }
    out
}

/// Header **placeholder** — `state_root` est à `ZERO`.
///
/// Ne l'utiliser que pour les tests qui échouent **avant** la
/// vérification du `state_root`. Pour les tests de succès, utiliser
/// [`build_block`].
fn header(height: u64, previous_block_hash: Hash32, base_fee: u128) -> BlockHeader {
    header_with_txs(height, previous_block_hash, base_fee, &[])
}

fn header_with_txs(
    height: u64,
    previous_block_hash: Hash32,
    base_fee: u128,
    txs: &[Transaction],
) -> BlockHeader {
    let receipts = expected_receipts_for_transfers(txs);
    // 4c.3.1b : `compute_transaction_root` prend désormais `&[Tx]`.
    // Les txs natives sont wrappées en `Tx::Native` — leur
    // `canonical_bytes()` reste identique à `encode_to_vec()`, donc la
    // valeur du root est inchangée.
    let wrapped: Vec<Tx> = txs.iter().cloned().map(Tx::Native).collect();
    BlockHeader {
        version: 1,
        chain_id: chain(),
        epoch: Epoch::new(0),
        height: Height::new(height),
        round: Round::new(0),
        previous_block_hash,
        timestamp: 1_700_000_000 + height,
        proposer_address: validator(),
        transaction_root: sango_exec::compute_transaction_root(&wrapped),
        state_root: Hash32::ZERO,
        receipt_root: sango_exec::compute_receipt_root(&receipts),
        gas_used: (txs.len() as u64).saturating_mul(NATIVE_TRANSFER_GAS),
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

// --- Premier bloc --------------------------------------------------------

#[test]
fn apply_first_block_ok() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::open(dir.path(), chain(), initial_supply()).unwrap();

    let block = build_block(&node, vec![]);
    let r = node.apply_block(&block, &[]).unwrap();
    assert!(r.apply_result.applied.is_empty());
    assert_eq!(r.gas_used, 0);
    assert_eq!(r.evm_state_root, sango_exec::empty_evm_state_root());
    assert_eq!(
        r.state_root,
        sango_state::global_state_root(r.native_state_root, r.evm_state_root)
    );

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
        evidences: Vec::new(),
        transactions: Vec::new(),
    };
    let err = node.apply_block(&block, &[]).unwrap_err();
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
        evidences: Vec::new(),
        transactions: Vec::new(),
    };
    let err = node.apply_block(&block, &[]).unwrap_err();
    assert!(matches!(err, sango_node::NodeError::HeightMismatch { .. }));
}

#[test]
fn first_block_wrong_base_fee_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::open(dir.path(), chain(), initial_supply()).unwrap();

    let block = Block {
        header: header(0, Hash32::ZERO, 42),
        evidences: Vec::new(),
        transactions: Vec::new(),
    };
    let err = node.apply_block(&block, &[]).unwrap_err();
    assert!(matches!(err, sango_node::NodeError::BaseFeeMismatch { .. }));
}

#[test]
fn first_block_wrong_transaction_root_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::open(dir.path(), chain(), initial_supply()).unwrap();

    let mut h = header(0, Hash32::ZERO, INITIAL_BASE_FEE);
    h.transaction_root = Hash32::from_bytes([0x77; 32]);
    let block = Block {
        header: h,
        evidences: Vec::new(),
        transactions: Vec::new(),
    };
    let err = node.apply_block(&block, &[]).unwrap_err();
    assert!(matches!(
        err,
        sango_node::NodeError::TransactionRootMismatch { .. }
    ));
}

#[test]
fn first_block_wrong_receipt_root_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::open(dir.path(), chain(), initial_supply()).unwrap();

    let mut h = header(0, Hash32::ZERO, INITIAL_BASE_FEE);
    h.receipt_root = Hash32::from_bytes([0x88; 32]);
    let block = Block {
        header: h,
        evidences: Vec::new(),
        transactions: Vec::new(),
    };
    let err = node.apply_block(&block, &[]).unwrap_err();
    assert!(matches!(
        err,
        sango_node::NodeError::ReceiptRootMismatch { .. }
    ));
}

#[test]
fn first_block_wrong_state_root_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::open(dir.path(), chain(), initial_supply()).unwrap();

    let mut block = build_block(&node, vec![]);
    // Modifie `state_root` — la vérification se déclenche après l'exécution,
    // donc rollback.
    block.header.state_root = Hash32::from_bytes([0x99; 32]);

    let err = node.apply_block(&block, &[]).unwrap_err();
    assert!(matches!(
        err,
        sango_node::NodeError::StateRootMismatch { .. }
    ));
    assert!(
        node.tip().is_none(),
        "rollback doit laisser le tip inchangé"
    );
}

// --- Chaînage -------------------------------------------------------------

#[test]
fn apply_two_empty_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::open(dir.path(), chain(), initial_supply()).unwrap();

    let b1 = build_block(&node, vec![]);
    let h1 = b1.hash();
    node.apply_block(&b1, &[]).unwrap();

    let b2 = build_block(&node, vec![]);
    assert_eq!(b2.header.previous_block_hash, h1);
    node.apply_block(&b2, &[]).unwrap();

    let tip = node.tip().unwrap();
    assert_eq!(tip.height.get(), 1);
    assert_eq!(tip.block_hash, b2.hash());
}

#[test]
fn second_block_wrong_parent_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::open(dir.path(), chain(), initial_supply()).unwrap();

    let b1 = build_block(&node, vec![]);
    node.apply_block(&b1, &[]).unwrap();

    let b2 = Block {
        header: header(1, Hash32::from_bytes([0xaa; 32]), INITIAL_BASE_FEE),
        evidences: Vec::new(),
        transactions: Vec::new(),
    };
    let err = node.apply_block(&b2, &[]).unwrap_err();
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
        evidences: Vec::new(),
        transactions: Vec::new(),
    };
    let err = node.apply_block(&block, &[]).unwrap_err();
    assert!(matches!(err, sango_node::NodeError::ChainIdMismatch));
}

// --- Transactions ---------------------------------------------------------

#[test]
fn reject_unknown_sender_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::open(dir.path(), chain(), initial_supply()).unwrap();

    let kp = NativeKeypair::from_seed([0x42; 32]);
    let tx = bootstrap_tx(&kp, 0, 100);

    // Ce test échoue à la validation (étape 4), avant les vérifications
    // de roots (5b/5c). `header_with_txs` calcule un `transaction_root`
    // et un `receipt_root` cohérents pour que l'échec soit bien celui
    // attendu.
    let block = Block {
        header: header_with_txs(0, Hash32::ZERO, INITIAL_BASE_FEE, std::slice::from_ref(&tx)),
        evidences: Vec::new(),
        transactions: vec![Tx::Native(tx)],
    };

    let err = node.apply_block(&block, &[]).unwrap_err();
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
        let block = build_block(&node, vec![]);
        let h = block.hash();
        node.apply_block(&block, &[]).unwrap();
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
        let block = build_block(&node, vec![]);
        node.apply_block(&block, &[]).unwrap();
        node.state().native_state_root()
    };

    let root_after = {
        let node = Node::open(dir.path(), chain(), initial_supply()).unwrap();
        node.state().native_state_root()
    };

    assert_eq!(root_before, root_after);
}
