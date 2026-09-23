//! Tests d'intégration du [`RoundRunner`].

use sango_consensus::{
    Action, ConsensusError, ConsensusState, LocalIdentity, RoundContext, RoundRunner, Step,
    Validator, ValidatorSet,
};
use sango_crypto::{derive_native_address, NativeKeypair};
use sango_primitives::{ChainId32, Epoch, Hash32, Height, NativeAddress, Round};
use sango_types::{Block, BlockHeader, Precommit, Prevote, Proposal};

// --- Helpers ---------------------------------------------------------------

fn chain() -> ChainId32 {
    ChainId32::from_bytes([0x11; 32])
}

fn parent() -> Hash32 {
    Hash32::from_bytes([0x99; 32])
}

fn make_validators(n: u8) -> (Vec<NativeKeypair>, Vec<NativeAddress>, ValidatorSet) {
    let mut kps = Vec::new();
    let mut addrs = Vec::new();
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
        addrs.push(address);
    }
    (kps, addrs, ValidatorSet::new(vs).unwrap())
}

fn empty_block(height: u64, round: u64) -> Block {
    Block {
        header: BlockHeader {
            version: 1,
            chain_id: chain(),
            epoch: Epoch::new(0),
            height: Height::new(height),
            round: Round::new(round),
            previous_block_hash: parent(),
            timestamp: 1_700_000_000,
            proposer_address: NativeAddress::ZERO,
            transaction_root: Hash32::ZERO,
            state_root: Hash32::ZERO,
            receipt_root: Hash32::ZERO,
            gas_used: 0,
            gas_limit: 30_000_000,
            base_fee: 1,
        },
        evidences: Vec::new(),
        transactions: Vec::new(),
    }
}

fn make_runner(ctx: RoundContext, vs: &ValidatorSet, kp: &NativeKeypair) -> RoundRunner {
    RoundRunner::new(
        ctx,
        vs.clone(),
        ConsensusState::new(Height::new(ctx.height.get())),
        Some(LocalIdentity::new(kp.clone())),
    )
}

fn build_proposal(ctx: &RoundContext, kp: &NativeKeypair, block: Block) -> Proposal {
    let block_hash = block.hash();
    let proposer_address = derive_native_address(&kp.public_key());
    Proposal {
        version: sango_types::PROTOCOL_VERSION_V1,
        chain_id: ctx.chain_id,
        epoch: ctx.epoch,
        height: ctx.height,
        round: ctx.round,
        block,
        block_hash,
        valid_round: None,
        valid_round_certificate: None,
        proposer_address,
        proposer_signature: sango_primitives::Signature::ZERO,
    }
    .sign(kp)
}

// --- Scénarios -------------------------------------------------------------

#[test]
fn four_validators_reach_commit() {
    let (kps, addrs, vs) = make_validators(4);
    let ctx = RoundContext {
        chain_id: chain(),
        epoch: Epoch::new(0),
        height: Height::new(1),
        round: Round::new(0),
        parent_hash: parent(),
    };

    let mut runners: Vec<RoundRunner> = kps.iter().map(|kp| make_runner(ctx, &vs, kp)).collect();

    // Identifier le proposer et l'index du keypair correspondant.
    let proposer_addr = runners[0].expected_proposer().unwrap();
    let proposer_idx = addrs.iter().position(|a| *a == proposer_addr).unwrap();

    // --- propose ---
    runners[proposer_idx].propose(empty_block(1, 0)).unwrap();

    let proposal = {
        let actions = runners[proposer_idx].drain_actions();
        actions
            .into_iter()
            .find_map(|a| match a {
                Action::BroadcastProposal(p) => Some(*p),
                _ => None,
            })
            .unwrap()
    };
    let block_hash = proposal.block_hash;

    // Distribute aux autres.
    for (i, r) in runners.iter_mut().enumerate() {
        if i == proposer_idx {
            continue;
        }
        r.on_proposal(proposal.clone()).unwrap();
    }

    // --- prevotes ---
    let prevotes: Vec<Prevote> = runners
        .iter_mut()
        .flat_map(|r| r.drain_actions())
        .filter_map(|a| match a {
            Action::BroadcastPrevote(p) => Some(p),
            _ => None,
        })
        .collect();
    for r in runners.iter_mut() {
        for p in &prevotes {
            // Ignorer le double vote éventuel (chaque validateur a déjà
            // enregistré son propre vote via cast_prevote).
            let _ = r.on_prevote(*p);
        }
    }
    for r in &runners {
        assert_eq!(r.step(), Step::Precommit);
    }

    // --- precommits ---
    let precommits: Vec<Precommit> = runners
        .iter_mut()
        .flat_map(|r| r.drain_actions())
        .filter_map(|a| match a {
            Action::BroadcastPrecommit(p) => Some(p),
            _ => None,
        })
        .collect();
    for r in runners.iter_mut() {
        for p in &precommits {
            let _ = r.on_precommit(*p);
        }
    }
    for r in &runners {
        assert!(r.is_committed());
        assert_eq!(r.step(), Step::Commit);
    }

    // Vérifier le certificat.
    let committed = runners[0]
        .drain_actions()
        .into_iter()
        .find_map(|a| match a {
            Action::Committed {
                block_hash: bh,
                certificate,
                ..
            } => Some((bh, certificate)),
            _ => None,
        })
        .expect("CommitCertificate");
    assert_eq!(committed.0, block_hash);
    assert!(committed.1.precommits.len() >= 3);
}

#[test]
fn invalid_proposal_does_not_transition() {
    let (kps, _addrs, vs) = make_validators(4);
    let ctx = RoundContext {
        chain_id: chain(),
        epoch: Epoch::new(0),
        height: Height::new(1),
        round: Round::new(0),
        parent_hash: parent(),
    };
    let mut runner = make_runner(ctx, &vs, &kps[0]);

    // Mauvais chain_id.
    let mut block = empty_block(1, 0);
    block.header.chain_id = ChainId32::from_bytes([0x99; 32]);
    let block_hash = block.hash();
    let bogus = Proposal {
        version: sango_types::PROTOCOL_VERSION_V1,
        chain_id: ChainId32::from_bytes([0x99; 32]),
        epoch: Epoch::new(0),
        height: Height::new(1),
        round: Round::new(0),
        block,
        block_hash,
        valid_round: None,
        valid_round_certificate: None,
        proposer_address: derive_native_address(&kps[0].public_key()),
        proposer_signature: sango_primitives::Signature::ZERO,
    };

    let err = runner.on_proposal(bogus).unwrap_err();
    assert!(matches!(err, ConsensusError::ChainIdMismatch { .. }));
    assert_eq!(runner.step(), Step::Propose);
}

#[test]
fn timeout_propose_votes_nil() {
    let (kps, _addrs, vs) = make_validators(4);
    let ctx = RoundContext {
        chain_id: chain(),
        epoch: Epoch::new(0),
        height: Height::new(1),
        round: Round::new(0),
        parent_hash: parent(),
    };
    let mut runner = make_runner(ctx, &vs, &kps[0]);
    runner.on_timeout_propose().unwrap();
    assert_eq!(runner.step(), Step::Prevote);

    let prevote = runner
        .drain_actions()
        .into_iter()
        .find_map(|a| match a {
            Action::BroadcastPrevote(p) => Some(p),
            _ => None,
        })
        .expect("precommit NIL émis");
    assert!(prevote.block_hash.is_none());
}

#[test]
fn timeout_chain_reaches_start_round() {
    let (kps, _addrs, vs) = make_validators(4);
    let ctx = RoundContext {
        chain_id: chain(),
        epoch: Epoch::new(0),
        height: Height::new(1),
        round: Round::new(0),
        parent_hash: parent(),
    };
    let mut runner = make_runner(ctx, &vs, &kps[0]);
    runner.on_timeout_propose().unwrap();
    runner.on_timeout_prevote().unwrap();
    assert_eq!(runner.step(), Step::Precommit);
    runner.on_timeout_precommit().unwrap();

    let start = runner
        .drain_actions()
        .into_iter()
        .find_map(|a| match a {
            Action::StartRound(r) => Some(r),
            _ => None,
        })
        .expect("StartRound");
    assert_eq!(start, Round::new(1));
}

#[test]
fn double_prevote_is_rejected() {
    let (kps, addrs, vs) = make_validators(4);
    let ctx = RoundContext {
        chain_id: chain(),
        epoch: Epoch::new(0),
        height: Height::new(1),
        round: Round::new(0),
        parent_hash: parent(),
    };
    // Runner avec l'identité de kps[3] (pas kps[0]) pour ne pas interférer
    // avec les votes que l'on va injecter.
    let mut runner = make_runner(ctx, &vs, &kps[3]);

    let signer = &kps[0];
    let addr = addrs[0];

    let make = |bh: Option<Hash32>| {
        Prevote {
            chain_id: chain(),
            epoch: Epoch::new(0),
            height: Height::new(1),
            round: Round::new(0),
            block_hash: bh,
            validator_address: addr,
            validator_signature: sango_primitives::Signature::ZERO,
        }
        .sign(signer)
    };

    let p1 = make(Some(Hash32::from_bytes([0xaa; 32])));
    let p2 = make(Some(Hash32::from_bytes([0xbb; 32])));

    runner.on_prevote(p1).unwrap();
    let err = runner.on_prevote(p2).unwrap_err();
    assert!(matches!(err, ConsensusError::DoublePrevote { .. }));
}

#[test]
fn non_validator_follows_without_voting() {
    let (kps, addrs, vs) = make_validators(4);
    let ctx = RoundContext {
        chain_id: chain(),
        epoch: Epoch::new(0),
        height: Height::new(1),
        round: Round::new(0),
        parent_hash: parent(),
    };
    let mut observer = RoundRunner::new(ctx, vs.clone(), ConsensusState::new(Height::new(1)), None);

    let proposer_addr = observer.expected_proposer().unwrap();
    let kp = kps
        .iter()
        .zip(addrs.iter())
        .find_map(|(kp, a)| if *a == proposer_addr { Some(kp) } else { None })
        .unwrap();

    let proposal = build_proposal(&ctx, kp, empty_block(1, 0));
    observer.on_proposal(proposal).unwrap();

    assert_eq!(observer.step(), Step::Prevote);
    assert!(observer.drain_actions().is_empty());
}

#[test]
fn validator_does_not_vote_twice_after_timeout() {
    let (kps, _addrs, vs) = make_validators(4);
    let ctx = RoundContext {
        chain_id: chain(),
        epoch: Epoch::new(0),
        height: Height::new(1),
        round: Round::new(0),
        parent_hash: parent(),
    };
    let mut runner = make_runner(ctx, &vs, &kps[0]);

    runner.on_timeout_propose().unwrap();
    let votes_after_timeout = runner
        .drain_actions()
        .into_iter()
        .filter(|a| matches!(a, Action::BroadcastPrevote(_)))
        .count();
    assert_eq!(votes_after_timeout, 1);

    // Une proposal arrive ensuite : on est déjà en Prevote, on ignore.
    let bogus = build_proposal(&ctx, &kps[0], empty_block(1, 0));
    runner.on_proposal(bogus).unwrap();
    assert!(runner.drain_actions().is_empty());
}
