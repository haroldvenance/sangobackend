//! Vérifie que 4 nodes ouverts avec le même genesis produisent le même state_root,
//! AVANT tout bloc.

use sango_crypto::{derive_native_address, NativeKeypair};
use sango_node::{Node, NodeHandle};
use sango_primitives::{Amount, ChainId32};
use sango_types::{NativeAccount, ValidatorInfo};

#[test]
fn four_nodes_same_genesis_same_root() {
    let chain_id = ChainId32::from_bytes([0x11; 32]);
    let supply = Amount::from_sango(1_000_000_000).unwrap();

    // Construire le genesis.
    let kps: Vec<_> = (0..4)
        .map(|i| NativeKeypair::from_seed([(i + 1) as u8; 32]))
        .collect();
    let mut accounts = Vec::new();
    let mut validators = Vec::new();
    for kp in &kps {
        let pk = kp.public_key();
        let address = derive_native_address(&pk);
        accounts.push(NativeAccount::from_public_key(
            pk,
            Amount::from_sango(100_000_000).unwrap(),
            0,
        ));
        validators.push(ValidatorInfo {
            address,
            public_key: pk,
            self_stake: Amount::from_sango(100_000).unwrap(),
            total_delegated: Amount::ZERO,
            commission_bps: 700,
            pending_commission_bps: None,
            pending_commission_at: None,
            jailed: false,
            jailed_until: None,
            downtime_window_start: 0,
            downtime_missed: 0,
        });
    }

    // 4 nodes ouverts avec le même genesis.
    let mut roots = Vec::new();
    let mut _dirs = Vec::new();
    for _ in 0..4 {
        let dir = tempfile::tempdir().unwrap();
        let mut node = Node::open(dir.path(), chain_id, supply).unwrap();
        node.initialize_genesis(&accounts, &validators).unwrap();
        let handle = NodeHandle::new(node);
        let root = handle.with_node(|n| n.state().native_state_root());
        roots.push(root);
        _dirs.push(dir);
    }

    eprintln!(
        "roots = {:?}",
        roots.iter().map(|r| r.to_hex()).collect::<Vec<_>>()
    );
    assert_eq!(roots[0], roots[1], "node 0 ≠ node 1");
    assert_eq!(roots[0], roots[2], "node 0 ≠ node 2");
    assert_eq!(roots[0], roots[3], "node 0 ≠ node 3");
}
