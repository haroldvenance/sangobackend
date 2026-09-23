//! Tests d'intégration du driver consensus avec un nœud réel.

use sango_consensus::{LocalIdentity, Validator, ValidatorSet};
use sango_crypto::{derive_native_address, NativeKeypair};
use sango_node::{Driver, Node, NodeHandle, OutgoingMessage};
use sango_primitives::{Amount, ChainId32, Epoch};

fn chain() -> ChainId32 {
    ChainId32::from_bytes([0x11; 32])
}

fn initial_supply() -> Amount {
    Amount::from_sango(1_000_000_000).unwrap()
}

fn make_validators(n: u8) -> (Vec<NativeKeypair>, ValidatorSet) {
    let mut kps = Vec::new();
    let mut vs = Vec::new();
    for i in 0..n {
        let kp = NativeKeypair::from_seed([i + 1; 32]);
        let pk = kp.public_key();
        let address = derive_native_address(&pk);
        vs.push(Validator {
            address,
            public_key: pk,
            voting_power: 100,
        });
        kps.push(kp);
    }
    (kps, ValidatorSet::new(vs).unwrap())
}

fn make_drivers(n: u8) -> (Vec<tempfile::TempDir>, Vec<Driver>) {
    let (kps, vs) = make_validators(n);
    let mut dirs = Vec::new();
    let mut drivers = Vec::new();
    for kp in kps.iter().take(n as usize) {
        let dir = tempfile::tempdir().unwrap();
        let node = Node::open(dir.path(), chain(), initial_supply()).unwrap();
        let handle = NodeHandle::new(node);
        let local = LocalIdentity::new(kp.clone());
        let d = Driver::new(handle, vs.clone(), Some(local), Epoch::new(0)).unwrap();
        dirs.push(dir);
        drivers.push(d);
    }
    (dirs, drivers)
}

fn run_until_height(drivers: &mut [Driver], target_height: u64) {
    for d in drivers.iter_mut() {
        d.maybe_propose().unwrap();
    }

    let max_iter = 200;
    for iter in 0..max_iter {
        let all_done = drivers.iter().all(|d| {
            d.node_handle().with_node(|n| {
                n.tip()
                    .map(|t| t.height.get() >= target_height)
                    .unwrap_or(false)
            })
        });
        if all_done {
            return;
        }
        assert!(iter < max_iter - 1, "did not reach target height");

        let mut proposals = Vec::new();
        let mut prevotes = Vec::new();
        let mut precommits = Vec::new();
        for d in drivers.iter_mut() {
            for msg in d.drain_outbox() {
                match msg {
                    OutgoingMessage::Proposal(p) => proposals.push(*p),
                    OutgoingMessage::Prevote(v) => prevotes.push(v),
                    OutgoingMessage::Precommit(c) => precommits.push(c),
                }
            }
        }
        let had_messages = !proposals.is_empty() || !prevotes.is_empty() || !precommits.is_empty();

        for d in drivers.iter_mut() {
            for p in &proposals {
                let _ = d.handle_proposal(p.clone());
            }
            for v in &prevotes {
                let _ = d.handle_prevote(*v);
            }
            for c in &precommits {
                let _ = d.handle_precommit(*c);
            }
        }

        for d in drivers.iter_mut() {
            d.maybe_propose().unwrap();
        }

        if !had_messages {
            for d in drivers.iter_mut() {
                let _ = d.handle_timeout();
            }
            for d in drivers.iter_mut() {
                d.maybe_propose().unwrap();
            }
        }
    }
}

// --- Tests -----------------------------------------------------------------

#[test]
fn single_validator_commits_one_block() {
    let (_dirs, mut drivers) = make_drivers(1);
    run_until_height(&mut drivers, 0);

    let tip = drivers[0].node_handle().with_node(|n| n.tip());
    assert_eq!(tip.unwrap().height.get(), 0);
}

#[test]
fn single_validator_commits_three_blocks() {
    let (_dirs, mut drivers) = make_drivers(1);
    run_until_height(&mut drivers, 2);

    let tip = drivers[0].node_handle().with_node(|n| n.tip());
    assert_eq!(tip.unwrap().height.get(), 2);
}

#[test]
fn four_validators_commit_three_blocks() {
    let (_dirs, mut drivers) = make_drivers(4);
    run_until_height(&mut drivers, 2);

    let tips: Vec<_> = drivers
        .iter()
        .map(|d| d.node_handle().with_node(|n| n.tip()).unwrap())
        .collect();
    for t in &tips {
        assert_eq!(t.height.get(), 2);
        assert_eq!(t.block_hash, tips[0].block_hash);
        assert_eq!(t.base_fee, tips[0].base_fee);
    }

    let roots: Vec<_> = drivers
        .iter()
        .map(|d| d.node_handle().with_node(|n| n.state().native_state_root()))
        .collect();
    for r in &roots {
        assert_eq!(*r, roots[0]);
    }
}

#[test]
fn four_validators_commit_six_blocks() {
    let (_dirs, mut drivers) = make_drivers(4);
    run_until_height(&mut drivers, 5);

    let tips: Vec<_> = drivers
        .iter()
        .map(|d| d.node_handle().with_node(|n| n.tip()).unwrap())
        .collect();
    for t in &tips {
        assert_eq!(t.height.get(), 5);
        assert_eq!(t.block_hash, tips[0].block_hash);
    }
}

#[test]
fn non_validator_follows_passively() {
    let (kps, vs) = make_validators(3);
    let mut dirs = Vec::new();
    let mut drivers = Vec::new();

    for kp in kps.iter().take(3) {
        let dir = tempfile::tempdir().unwrap();
        let node = Node::open(dir.path(), chain(), initial_supply()).unwrap();
        let handle = NodeHandle::new(node);
        let local = LocalIdentity::new(kp.clone());
        drivers.push(Driver::new(handle, vs.clone(), Some(local), Epoch::new(0)).unwrap());
        dirs.push(dir);
    }
    {
        let dir = tempfile::tempdir().unwrap();
        let node = Node::open(dir.path(), chain(), initial_supply()).unwrap();
        let handle = NodeHandle::new(node);
        drivers.push(Driver::new(handle, vs.clone(), None, Epoch::new(0)).unwrap());
        dirs.push(dir);
    }

    run_until_height(&mut drivers, 1);

    let observer_tip = drivers[3].node_handle().with_node(|n| n.tip());
    assert_eq!(observer_tip.unwrap().height.get(), 1);
}
