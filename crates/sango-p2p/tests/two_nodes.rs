//! Test d'intégration : deux nœuds P2P qui communiquent.
//!
//! ## Scénario
//!
//! 1. On démarre deux services P2P avec mDNS désactivé.
//! 2. On les connecte manuellement via `dial`.
//! 3. On envoie un message depuis le nœud A.
//! 4. On vérifie qu'il est reçu par le nœud B.

use std::time::Duration;

use sango_p2p::{spawn_with_events, NetworkMessage, P2pConfig, P2pEvent};
use sango_primitives::{Amount, ChainId32, NativeAddress, Signature};
use sango_types::{Transaction, TxKind};
use tokio::time::timeout;

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_nodes_exchange_message() {
    // 1. Démarrer deux services P2P sur des ports OS-assignés.
    let cfg = P2pConfig {
        mdns_enabled: false,
        ..Default::default()
    };
    let (handle_a, mut events_a) = spawn_with_events(cfg.clone()).unwrap();
    let (handle_b, mut events_b) = spawn_with_events(cfg).unwrap();

    let peer_a = handle_a.service.local_peer_id();
    let peer_b = handle_b.service.local_peer_id();

    // 2. Attendre que les deux aient une adresse d'écoute.
    //    On récupère l'adresse via les events `NewListenAddr`.
    let addr_a = wait_for_listen_addr(&mut events_a).await;
    let addr_b = wait_for_listen_addr(&mut events_b).await;

    eprintln!("node A: peer={peer_a} addr={addr_a}");
    eprintln!("node B: peer={peer_b} addr={addr_b}");

    // 3. Dial mutuel.
    handle_a.service.dial(addr_b.clone(), peer_b).await.unwrap();
    handle_b.service.dial(addr_a.clone(), peer_a).await.unwrap();

    // 4. Attendre que les deux soient connectés.
    wait_for_connected(&mut events_a).await;
    wait_for_connected(&mut events_b).await;

    // 5. Attendre que les topics gossipsub soient souscrits (health
    //    propagation). On laisse un peu de temps pour que gossipsub
    //    échange les subscriptions.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 6. A publie une tx.
    let tx = dummy_tx(42);
    let expected = NetworkMessage::Transaction(tx.clone());
    handle_a.service.broadcast(expected.clone()).await.unwrap();

    // 7. B doit recevoir.
    let received = timeout(Duration::from_secs(5), async {
        loop {
            match events_b.recv().await {
                Some(P2pEvent::Message { message, .. }) => {
                    return *message;
                }
                Some(_) => continue,
                None => panic!("events_b closed"),
            }
        }
    })
    .await
    .expect("timeout waiting for message");

    assert_eq!(received, expected);

    // 8. Shutdown.
    handle_a.service.shutdown().await.unwrap();
    handle_b.service.shutdown().await.unwrap();
    let _ = handle_a.task.await;
    let _ = handle_b.task.await;
}

async fn wait_for_listen_addr(
    events: &mut tokio::sync::mpsc::Receiver<P2pEvent>,
) -> libp2p::Multiaddr {
    // Note : P2pEvent n'expose pas directement `NewListenAddr`. On doit
    // donc passer par un canal dédié ou modifier l'API. Pour ce test,
    // on utilise une astuce : la config utilise un port fixe dédié.
    //
    // **Limitation** : en pratique, on devrait exposer les `NewListenAddr`
    // via `P2pEvent`. C'est un TODO(P2) quand on intégrera dans le Driver.
    let _ = events;
    panic!("à implémenter en P2 : exposer NewListenAddr via P2pEvent");
}

async fn wait_for_connected(events: &mut tokio::sync::mpsc::Receiver<P2pEvent>) {
    let _ = events;
    // Également délégué à P2.
}
