//! Test d'intégration : 4 validateurs connectés via P2P convergent.

use std::thread;
use std::time::{Duration, Instant};

use sango_consensus::{LocalIdentity, Validator, ValidatorSet};
use sango_crypto::{derive_native_address, NativeKeypair};
use sango_node::{Driver, Node, NodeHandle, OutgoingMessage};
use sango_p2p::multiaddr::Protocol;
use sango_p2p::{Multiaddr, P2pConfig, P2pEvent, P2pService};
use sango_primitives::{Amount, ChainId32, Epoch, Hash32};
use sango_types::{NativeAccount, ValidatorInfo};
use tokio::runtime::Runtime;

const CHAIN_ID_BYTES: [u8; 32] = [0x11; 32];
const INITIAL_SUPPLY_SANGO: u128 = 1_000_000_000;
const NUM_VALIDATORS: usize = 4;
const TARGET_HEIGHT: u64 = 3;
const TEST_TIMEOUT: Duration = Duration::from_secs(25);
const TICK_INTERVAL: Duration = Duration::from_millis(50);
const GOSSIP_HEARTBEAT: Duration = Duration::from_millis(200);
const STAGNATION_TIMEOUT: Duration = Duration::from_millis(2500);

fn chain() -> ChainId32 {
    ChainId32::from_bytes(CHAIN_ID_BYTES)
}

fn make_validators() -> Vec<NativeKeypair> {
    (0..NUM_VALIDATORS)
        .map(|i| NativeKeypair::from_seed([(i + 1) as u8; 32]))
        .collect()
}

fn build_genesis_data(kps: &[NativeKeypair]) -> (Vec<NativeAccount>, Vec<ValidatorInfo>) {
    let mut accounts = Vec::with_capacity(kps.len());
    let mut validators = Vec::with_capacity(kps.len());
    for kp in kps {
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
    (accounts, validators)
}

fn wait_for_listen_addr(svc: &P2pService, timeout: Duration) -> Multiaddr {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(P2pEvent::NewListenAddr(a)) = svc.try_recv_event() {
            return a;
        }
        if Instant::now() > deadline {
            panic!("timeout waiting for NewListenAddr");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// Retourne `(next_height, root)`.
///
/// `next_height` = hauteur du **prochain** bloc à proposer (i.e.
/// `tip.height + 1`, ou `0` si aucun tip). Distingue donc correctement
/// « avant tout commit » (0) de « h=0 commité » (1).
fn snapshot(driver: &Driver) -> (u64, Hash32) {
    driver.node_handle().with_node(|n| {
        let h = n.tip().map(|t| t.height.get() + 1).unwrap_or(0);
        let r = n.state().native_state_root();
        (h, r)
    })
}

#[test]
fn four_validators_converge_via_p2p() {
    let rt = Runtime::new().expect("tokio runtime");
    let _guard = rt.enter();

    let kps = make_validators();
    let (accounts, validator_infos) = build_genesis_data(&kps);
    let chain_id = chain();
    let initial_supply = Amount::from_sango(INITIAL_SUPPLY_SANGO).unwrap();

    // --- 1. Services P2P ---
    let mut p2p_handles = Vec::with_capacity(NUM_VALIDATORS);
    for _ in 0..NUM_VALIDATORS {
        let cfg = P2pConfig {
            listen_addrs: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
            mdns_enabled: false,
            gossipsub_heartbeat: GOSSIP_HEARTBEAT,
            ..Default::default()
        };
        p2p_handles.push(sango_p2p::spawn(cfg).expect("spawn p2p"));
    }

    let mut peer_addrs: Vec<(Multiaddr, sango_p2p::PeerId)> = Vec::with_capacity(NUM_VALIDATORS);
    for h in &p2p_handles {
        let addr = wait_for_listen_addr(&h.service, Duration::from_secs(5));
        peer_addrs.push((addr, h.service.local_peer_id()));
    }
    eprintln!("[test] {NUM_VALIDATORS} services P2P démarrés");

    // --- 2. Nœuds ---
    let mut dirs = Vec::with_capacity(NUM_VALIDATORS);
    let mut node_handles = Vec::with_capacity(NUM_VALIDATORS);
    for i in 0..NUM_VALIDATORS {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut node = Node::open(dir.path(), chain_id, initial_supply).expect("open node");
        node.initialize_genesis(&accounts, &validator_infos)
            .expect("init genesis");
        eprintln!(
            "[test] node {i} genesis root = {}",
            node.state().native_state_root().to_hex()
        );
        node_handles.push(NodeHandle::new(node));
        dirs.push(dir);
    }

    let vs = ValidatorSet::new(
        validator_infos
            .iter()
            .map(|v| Validator {
                address: v.address,
                public_key: v.public_key,
                voting_power: v.voting_power().base_units(),
            })
            .collect(),
    )
    .expect("validator set");

    // --- 3. Drivers ---
    let mut drivers = Vec::with_capacity(NUM_VALIDATORS);
    for (i, kp) in kps.iter().enumerate() {
        let mut d = Driver::new(
            node_handles[i].clone(),
            vs.clone(),
            Some(LocalIdentity::new(kp.clone())),
            Epoch::new(0),
        )
        .expect("driver new");
        d.attach_p2p(p2p_handles[i].service.clone());
        drivers.push(d);
    }

    // --- 4. Full mesh : double dial ---
    for _ in 0..2 {
        for (i, handle) in p2p_handles.iter().enumerate() {
            for (j, (addr, peer_id)) in peer_addrs.iter().enumerate() {
                if i == j {
                    continue;
                }
                let mut full = addr.clone();
                full.push(Protocol::P2p(*peer_id));
                let _ = handle.service.dial_sync(full);
            }
        }
        thread::sleep(Duration::from_millis(1000));
    }
    eprintln!("[test] gossipsub stabilisé, début boucle consensus");

    // --- 5. Boucle ---
    let deadline = Instant::now() + TEST_TIMEOUT;
    let mut last_report = Instant::now();
    let mut last_progress: Vec<Instant> = vec![Instant::now(); NUM_VALIDATORS];
    let mut last_heights: Vec<u64> = vec![0; NUM_VALIDATORS];
    let mut iter_count: u32 = 0;

    while Instant::now() < deadline {
        iter_count += 1;

        // 5a. Drain P2P.
        for d in drivers.iter_mut() {
            let _ = d.drain_p2p_events(500);
        }

        // 5b. Peut-on proposer ?
        //     On exige que tous les nœuds soient sur la **même** hauteur
        //     suivante. `snapshot` renvoie `tip.height + 1`, donc :
        //       * tip=None       → 0 (prochain bloc = h0)
        //       * tip.height=0   → 1 (prochain bloc = h1)
        //       * tip.height=1   → 2
        //     Deux nœuds sont alignés ssi leurs prochaines hauteurs sont
        //     égales. On évite ainsi le faux positif « h0 pas encore
        //     commité == h0 commité ».
        let nexts: Vec<u64> = drivers.iter().map(|d| snapshot(d).0).collect();
        let all_aligned = nexts.iter().all(|h| *h == nexts[0]);

        if all_aligned {
            for d in drivers.iter_mut() {
                let _ = d.maybe_propose();
            }
            for d in drivers.iter_mut() {
                let outgoing = d.drain_outbox();
                for msg in outgoing {
                    match msg {
                        OutgoingMessage::Proposal(p) => {
                            let _ = d.handle_proposal(*p);
                        }
                        OutgoingMessage::Prevote(v) => {
                            let _ = d.handle_prevote(v);
                        }
                        OutgoingMessage::Precommit(c) => {
                            let _ = d.handle_precommit(c);
                        }
                    }
                }
            }
        }

        // 5c. Events.
        for d in drivers.iter_mut() {
            let _ = d.drain_events();
        }

        // 5d. Timeout recovery : uniquement pour Prevote / Precommit.
        //     Un nœud bloqué à Propose doit attendre le proposeur (sinon
        //     il vote NIL avant même que le proposeur ait proposé).
        let now = Instant::now();
        for (i, d) in drivers.iter_mut().enumerate() {
            let (h, _) = snapshot(d);
            if h > last_heights[i] {
                last_heights[i] = h;
                last_progress[i] = now;
            } else if now.duration_since(last_progress[i]) > STAGNATION_TIMEOUT
                && d.current_step() != sango_consensus::Step::Propose
            {
                let _ = d.handle_timeout();
                last_progress[i] = now;
            }
        }

        // 5e. Snapshot / rapport.
        let snaps: Vec<(u64, Hash32)> = drivers.iter().map(snapshot).collect();
        let heights: Vec<u64> = snaps.iter().map(|(h, _)| *h).collect();
        let roots: Vec<Hash32> = snaps.iter().map(|(_, r)| *r).collect();

        if iter_count <= 20 || last_report.elapsed() >= Duration::from_secs(2) {
            let roots_short: Vec<String> =
                roots.iter().map(|r| r.to_hex()[..8].to_string()).collect();
            eprintln!("[iter {iter_count:02}] next_heights={heights:?} roots={roots_short:?}");
            last_report = Instant::now();
        }

        // 5f. Convergence : on veut `next_height > TARGET_HEIGHT` partout
        //     (i.e. hauteur courante ≥ TARGET_HEIGHT) + même root.
        let all_same = heights.iter().all(|h| *h == heights[0]);
        let all_same_root = roots.iter().all(|r| *r == roots[0]);
        let target_reached = heights.iter().all(|h| *h > TARGET_HEIGHT);

        if target_reached && all_same && all_same_root {
            eprintln!(
                "[test] ✓ CONVERGENCE : 4 validateurs, next_height={}, root={}",
                heights[0],
                roots[0].to_hex()
            );
            for h in &p2p_handles {
                h.service.shutdown_sync().ok();
            }
            return;
        }

        thread::sleep(TICK_INTERVAL);
    }

    let snaps: Vec<(u64, Hash32)> = drivers.iter().map(snapshot).collect();
    let heights: Vec<u64> = snaps.iter().map(|(h, _)| *h).collect();
    let roots: Vec<String> = snaps
        .iter()
        .map(|(_, r)| r.to_hex()[..16].to_string())
        .collect();
    panic!(
        "convergence échouée après {:?}\nnext_heights = {heights:?}\nroots = {roots:?}",
        TEST_TIMEOUT
    );
}
