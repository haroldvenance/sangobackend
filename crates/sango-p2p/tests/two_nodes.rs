//! Test d'intégration : deux nœuds P2P qui communiquent.
//!
//! ## Scénario
//!
//! 1. Démarre deux services P2P (mDNS désactivé, ports OS-assignés).
//! 2. Attend l'événement `NewListenAddr` de chacun.
//! 3. A dial B.
//! 4. Attend `PeerConnected` des deux côtés.
//! 5. Attend que gossipsub échange les souscriptions.
//! 6. A publie une transaction.
//! 7. B la reçoit.
//!
//! ## Runtime
//!
//! Le test utilise un runtime tokio multi-thread créé manuellement. Le
//! runtime reste vivant tant que `_rt` n'est pas droppé, ce qui garantit
//! que la tâche du swarm continue de tourner.

use std::time::Duration;

use sango_p2p::{spawn, NetworkMessage, P2pConfig, P2pEvent};
use sango_primitives::{Amount, ChainId32, NativeAddress, Signature};
use sango_types::{Transaction, TxKind};
use tokio::runtime::Runtime;

fn chain() -> ChainId32 {
    ChainId32::from_bytes([0x11; 32])
}

fn dummy_tx(nonce: u64) -> Transaction {
    Transaction {
        version: 1,
        chain_id: chain(),
        nonce,
        sender: NativeAddress::from_bytes([0xaa; 20]),
        public_key: None,
        gas_limit: 21_000,
        max_fee: 20,
        priority_fee: 2,
        value: Amount::from_base_units(100),
        tx_kind: TxKind::Transfer,
        recipient: Some(NativeAddress::from_bytes([0xbb; 20])),
        data: Vec::new(),
        signature: Signature::ZERO,
    }
}

/// Poll les événements d'un service jusqu'à en trouver un qui matche.
///
/// Timeout global : 5 secondes. Poll interval : 10 ms.
fn wait_for<F, T>(service: &sango_p2p::P2pService, mut predicate: F) -> T
where
    F: FnMut(&P2pEvent) -> Option<T>,
{
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        while let Some(event) = service.try_recv_event() {
            if let Some(v) = predicate(&event) {
                return v;
            }
            // ignore les autres événements
        }
        if std::time::Instant::now() > deadline {
            panic!("timeout waiting for event");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn two_nodes_exchange_message() {
    let rt = Runtime::new().expect("tokio runtime");
    let _guard = rt.enter();

    let cfg = P2pConfig {
        mdns_enabled: false,
        ..Default::default()
    };

    let handle_a = spawn(cfg.clone()).expect("spawn A");
    let handle_b = spawn(cfg).expect("spawn B");

    let peer_a = handle_a.service.local_peer_id();
    let peer_b = handle_b.service.local_peer_id();
    assert_ne!(peer_a, peer_b, "les PeerId doivent être distincts");

    // 1. Attendre les adresses d'écoute.
    let addr_a = wait_for(&handle_a.service, |e| match e {
        P2pEvent::NewListenAddr(a) => Some(a.clone()),
        _ => None,
    });
    let addr_b = wait_for(&handle_b.service, |e| match e {
        P2pEvent::NewListenAddr(a) => Some(a.clone()),
        _ => None,
    });

    eprintln!("node A: peer={peer_a} addr={addr_a}");
    eprintln!("node B: peer={peer_b} addr={addr_b}");

    // 2. A dial B.
    handle_a
        .service
        .dial_sync(addr_b.clone())
        .expect("dial B from A");

    // 3. Attendre PeerConnected des deux côtés.
    let _ = wait_for(&handle_a.service, |e| match e {
        P2pEvent::PeerConnected(p) if *p == peer_b => Some(*p),
        _ => None,
    });
    let _ = wait_for(&handle_b.service, |e| match e {
        P2pEvent::PeerConnected(p) if *p == peer_a => Some(*p),
        _ => None,
    });

    // 4. Attendre la propagation des souscriptions gossipsub.
    wait_for(&handle_a.service, |e| match e {
        P2pEvent::Subscribed { peer_id, .. } if *peer_id == peer_b => Some(()),
        _ => None,
    });

    // 5. A publie une tx.
    let tx = dummy_tx(42);
    let expected = NetworkMessage::Transaction(tx);
    handle_a
        .service
        .broadcast_sync(expected.clone())
        .expect("broadcast");

    // 6. B doit recevoir.
    let received = wait_for(&handle_b.service, |e| match e {
        P2pEvent::Message { message, .. } => Some((**message).clone()),
        _ => None,
    });

    assert_eq!(received, expected);

    // 7. Shutdown.
    handle_a.service.shutdown_sync().ok();
    handle_b.service.shutdown_sync().ok();
    drop(rt);
}
