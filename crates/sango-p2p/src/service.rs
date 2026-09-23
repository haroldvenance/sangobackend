//! Service P2P basé sur libp2p.
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────┐    P2pCommand     ┌─────────────────────┐
//! │   Driver     │ ────────────────► │                     │
//! │              │                    │   P2pService        │
//! │              │ ◄──────────────── │   (handle)          │
//! └──────────────┘     P2pEvent      │                     │
//!                                    │  ┌───────────────┐  │
//!                                    │  │  libp2p Swarm │  │
//!                                    │  │  - QUIC       │  │
//!                                    │  │  - gossipsub  │  │
//!                                    │  │  - mDNS       │  │
//!                                    │  │  - ping       │  │
//!                                    │  └───────────────┘  │
//!                                    └─────────────────────┘
//! ```
//!
//! Le service tourne dans une tâche tokio dédiée. Le `Driver` communique
//! avec lui via deux canaux mpsc :
//!
//! - `P2pCommand` : driver → réseau (publish, dial, shutdown) ;
//! - `P2pEvent` : réseau → driver (message reçu, peer connecté).

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;

use futures::StreamExt;
use libp2p::{
    gossipsub, identity, mdns, ping,
    swarm::{NetworkBehaviour, SwarmEvent},
    Multiaddr, PeerId, Swarm,
};
use tokio::sync::mpsc;

use sango_codec::{Decode as _, Encode};

use crate::config::P2pConfig;
use crate::error::P2pError;
use crate::message::{MessageType, NetworkMessage};
use crate::topics;

/// Événement produit par le service P2P.
#[derive(Debug)]
pub enum P2pEvent {
    /// Un message a été reçu (décodé).
    Message {
        /// Peer émetteur (au niveau réseau, pas validateur).
        from: PeerId,
        /// Message.
        message: Box<NetworkMessage>,
    },
    /// Un nouveau peer s'est connecté.
    PeerConnected(PeerId),
    /// Un peer s'est déconnecté.
    PeerDisconnected(PeerId),
    /// Erreur de transport (loggée, non-fatale).
    TransportError(String),
}

/// Commande envoyée au service P2P par le driver.
#[derive(Debug)]
pub enum P2pCommand {
    /// Publier un message sur le topic approprié.
    Broadcast(NetworkMessage),
    /// Se connecter à un peer (adresse + PeerId).
    Dial(Multiaddr, PeerId),
    /// Arrêter le service.
    Shutdown,
}

/// Handle clonable vers le service P2P.
#[derive(Clone)]
pub struct P2pService {
    cmd_tx: mpsc::Sender<P2pCommand>,
    local_peer_id: PeerId,
    local_addr: Option<Multiaddr>,
}

impl P2pService {
    /// Retourne le `PeerId` local (identité réseau).
    #[must_use]
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// Retourne l'adresse locale d'écoute (si le swarm a bindé).
    #[must_use]
    pub fn local_addr(&self) -> Option<&Multiaddr> {
        self.local_addr.as_ref()
    }

    /// Publie un message sur le topic correspondant.
    pub async fn broadcast(&self, message: NetworkMessage) -> Result<(), P2pError> {
        self.cmd_tx
            .send(P2pCommand::Broadcast(message))
            .await
            .map_err(|_| P2pError::ChannelClosed)
    }

    /// Se connecte à un peer.
    pub async fn dial(&self, addr: Multiaddr, peer_id: PeerId) -> Result<(), P2pError> {
        self.cmd_tx
            .send(P2pCommand::Dial(addr, peer_id))
            .await
            .map_err(|_| P2pError::ChannelClosed)
    }

    /// Demande l'arrêt du service.
    pub async fn shutdown(&self) -> Result<(), P2pError> {
        self.cmd_tx
            .send(P2pCommand::Shutdown)
            .await
            .map_err(|_| P2pError::ChannelClosed)
    }
}

impl std::fmt::Debug for P2pService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P2pService")
            .field("local_peer_id", &self.local_peer_id)
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

/// Résultat du démarrage du service : handle + task join handle.
pub struct P2pHandle {
    /// Handle clonable pour envoyer des commandes.
    pub service: P2pService,
    /// Tâche tokio à joindre en fin de vie.
    pub task: tokio::task::JoinHandle<Result<(), P2pError>>,
}

/// Démarre le service P2P.
///
/// Crée le swarm, binde les adresses d'écoute, souscrit aux topics, et
/// lance la boucle événementielle dans une tâche tokio.
///
/// # Erreurs
///
/// - [`P2pError::Transport`] si le swarm ne peut pas être créé.
/// - [`P2pError::Subscription`] si la souscription gossipsub échoue.
pub fn spawn(cfg: P2pConfig) -> Result<P2pHandle, P2pError> {
    let (cmd_tx, cmd_rx) = mpsc::channel::<P2pCommand>(1024);
    let (event_tx, _event_rx) = mpsc::channel::<P2pEvent>(1024);

    // On crée le swarm de manière synchrone pour pouvoir extraire le
    // PeerId et les addresses avant de lancer la tâche.
    let (swarm, local_peer_id, local_addr) = build_swarm(&cfg)?;

    let cmd_tx_clone = cmd_tx.clone();
    let task = tokio::spawn(async move { run_swarm(swarm, cmd_rx, event_tx, cmd_tx_clone).await });

    Ok(P2pHandle {
        service: P2pService {
            cmd_tx,
            local_peer_id,
            local_addr,
        },
        task,
    })
}

/// Démarre le service P2P avec un canal d'événements externe (utile pour
/// les tests où l'on veut consommer les événements directement).
pub fn spawn_with_events(
    cfg: P2pConfig,
) -> Result<(P2pHandle, mpsc::Receiver<P2pEvent>), P2pError> {
    let (cmd_tx, cmd_rx) = mpsc::channel::<P2pCommand>(1024);
    let (event_tx, event_rx) = mpsc::channel::<P2pEvent>(1024);

    let (swarm, local_peer_id, local_addr) = build_swarm(&cfg)?;

    let cmd_tx_clone = cmd_tx.clone();
    let task = tokio::spawn(async move { run_swarm(swarm, cmd_rx, event_tx, cmd_tx_clone).await });

    Ok((
        P2pHandle {
            service: P2pService {
                cmd_tx,
                local_peer_id,
                local_addr,
            },
            task,
        },
        event_rx,
    ))
}

// --- Construction du swarm --------------------------------------------------

#[derive(NetworkBehaviour)]
struct SangoBehaviour {
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
    ping: ping::Behaviour,
}

fn build_swarm(
    cfg: &P2pConfig,
) -> Result<(Swarm<SangoBehaviour>, PeerId, Option<Multiaddr>), P2pError> {
    // Identité P2P (Ed25519 par défaut libp2p). Distincte de l'identité
    // validateur.
    let keypair = identity::Keypair::generate_ed25519();

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_quic()
        .with_behaviour(|key| {
            // Configuration gossipsub.
            let gs_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(cfg.gossipsub_heartbeat)
                .max_transmit_size(cfg.max_message_size)
                .validation_mode(gossipsub::ValidationMode::Strict)
                .build()
                .map_err(|e| P2pError::Config(format!("gossipsub config: {e}")))?;

            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gs_config,
            )
            .map_err(|e| P2pError::Config(format!("gossipsub behaviour: {e}")))?;

            // mDNS (devnet uniquement).
            let mdns = if cfg.mdns_enabled {
                mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())
                    .map_err(|e| P2pError::Config(format!("mdns: {e}")))?
            } else {
                // mDNS inactif : on l'active quand même mais on ne l'utilisera
                // pas. Ça évite de complexifier le type du behaviour.
                mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())
                    .map_err(|e| P2pError::Config(format!("mdns: {e}")))?
            };

            let ping = ping::Behaviour::new(
                ping::Config::new()
                    .with_interval(Duration::from_secs(15))
                    .with_timeout(Duration::from_secs(20)),
            );

            Ok(SangoBehaviour {
                gossipsub,
                mdns,
                ping,
            })
        })
        .map_err(|e| P2pError::Config(format!("swarm builder behaviour: {e}")))?
        .build();

    // Souscrire aux topics.
    for topic_str in topics::ALL_TOPICS {
        let topic = gossipsub::IdentTopic::new(*topic_str);
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&topic)
            .map_err(|e| P2pError::Subscription(format!("{topic_str}: {e}")))?;
    }

    // Bind des adresses d'écoute.
    let mut bound_addr: Option<Multiaddr> = None;
    for addr in &cfg.listen_addrs {
        swarm
            .listen_on(addr.clone())
            .map_err(|e| P2pError::Transport(format!("listen_on {addr}: {e}")))?;
        // On enregistre la première adresse comme "locale" (les autres
        // seront complétées par les events `NewListenAddr`).
        if bound_addr.is_none() {
            bound_addr = Some(addr.clone());
        }
    }

    // Ajouter les peers bootstrap en known_peers (déclenche les dials
    // via l'événement mdns ou le comportement de découverte).
    for (addr, peer_id) in &cfg.bootstrap_addrs {
        swarm.behaviour_mut().gossipsub.add_explicit_peer(peer_id);
        // On ne dial pas immédiatement : on le fera dès que le swarm est
        // prêt (dans la boucle run_swarm).
        let _ = addr;
    }

    let local_peer_id = *swarm.local_peer_id();
    Ok((swarm, local_peer_id, bound_addr))
}

// --- Boucle événementielle --------------------------------------------------

async fn run_swarm(
    mut swarm: Swarm<SangoBehaviour>,
    mut cmd_rx: mpsc::Receiver<P2pCommand>,
    event_tx: mpsc::Sender<P2pEvent>,
    _cmd_tx: mpsc::Sender<P2pCommand>,
) -> Result<(), P2pError> {
    // Dial les bootstrap au démarrage (fire-and-forget).
    // On répète à intervalle pour rattraper les peers pas encore prêts.
    let mut bootstrap_tick = tokio::time::interval(Duration::from_secs(5));
    let _ = bootstrap_tick.tick().await; // skip immediate tick

    loop {
        tokio::select! {
            // --- Commandes entrantes -----------------------------------------
            cmd = cmd_rx.recv() => {
                match cmd {
                    None => {
                        // Canal fermé → shutdown.
                        return Ok(());
                    }
                    Some(P2pCommand::Shutdown) => {
                        return Ok(());
                    }
                    Some(P2pCommand::Dial(addr, _peer_id)) => {
                        if let Err(e) = swarm.dial(addr.clone()) {
                            let _ = event_tx.send(P2pEvent::TransportError(
                                format!("dial {addr}: {e}")
                            )).await;
                        }
                    }
                    Some(P2pCommand::Broadcast(msg)) => {
                        if let Err(e) = publish(&mut swarm, &msg) {
                            let _ = event_tx.send(P2pEvent::TransportError(
                                format!("publish: {e}")
                            )).await;
                        }
                    }
                }
            }

            // --- Événements du swarm ----------------------------------------
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        tracing_print(&format!("[p2p] listening on {address}"));
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        let _ = event_tx.send(P2pEvent::PeerConnected(peer_id)).await;
                    }
                    SwarmEvent::ConnectionClosed { peer_id, .. } => {
                        let _ = event_tx.send(P2pEvent::PeerDisconnected(peer_id)).await;
                    }
                    SwarmEvent::Behaviour(SangoBehaviourEvent::Mdns(
                        mdns::Event::Discovered(peers)
                    )) => {
                        for (peer_id, addr) in peers {
                            swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                            if let Err(e) = swarm.dial(addr.clone()) {
                                let _ = event_tx.send(P2pEvent::TransportError(
                                    format!("dial mdns {addr}: {e}")
                                )).await;
                            }
                        }
                    }
                    SwarmEvent::Behaviour(SangoBehaviourEvent::Mdns(
                        mdns::Event::Expired(peers)
                    )) => {
                        for (peer_id, _) in peers {
                            swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                        }
                    }
                    SwarmEvent::Behaviour(SangoBehaviourEvent::Gossipsub(
                        gossipsub::Event::Message { propagation_source, message, .. }
                    )) => {
                        match NetworkMessage::decode_exact(&message.data) {
                            Ok(msg) => {
                                let _ = event_tx.send(P2pEvent::Message {
                                    from: propagation_source,
                                    message: Box::new(msg),
                                }).await;
                            }
                            Err(e) => {
                                let _ = event_tx.send(P2pEvent::TransportError(
                                    format!("decode message from {propagation_source}: {e}")
                                )).await;
                            }
                        }
                    }
                    SwarmEvent::Behaviour(SangoBehaviourEvent::Gossipsub(
                        gossipsub::Event::Subscribed { peer_id, topic }
                    )) => {
                        tracing_print(&format!("[p2p] {peer_id} subscribed to {topic}"));
                    }
                    SwarmEvent::Behaviour(SangoBehaviourEvent::Gossipsub(
                        gossipsub::Event::Unsubscribed { peer_id, topic }
                    )) => {
                        tracing_print(&format!("[p2p] {peer_id} unsubscribed from {topic}"));
                    }
                    _ => { /* ignorer les autres */ }
                }
            }

            // --- Retry bootstrap --------------------------------------------
            _ = bootstrap_tick.tick() => {
                // Rien pour l'instant : les bootstrap_addrs ne sont dial
                // qu'au démarrage. À compléter quand on aura le PeerId
                // bootstrap stocké dans le swarm.
            }
        }
    }
}

fn publish(swarm: &mut Swarm<SangoBehaviour>, msg: &NetworkMessage) -> Result<(), P2pError> {
    let topic = topic_for(msg.message_type());
    let bytes = msg.encode_to_vec();
    swarm
        .behaviour_mut()
        .gossipsub
        .publish(gossipsub::IdentTopic::new(topic), bytes)
        .map_err(|e| P2pError::Transport(format!("gossipsub publish: {e}")))?;
    Ok(())
}

fn topic_for(mt: MessageType) -> &'static str {
    match mt {
        MessageType::Proposal | MessageType::Prevote | MessageType::Precommit => {
            topics::TOPIC_CONSENSUS
        }
        MessageType::Transaction => topics::TOPIC_TX,
        MessageType::Block => topics::TOPIC_BLOCK,
    }
}

fn tracing_print(msg: &str) {
    // Pas de tracing dans V1 — on imprime directement.
    eprintln!("{msg}");
}

// Marqueur pour `DefaultHasher` importé mais non utilisé pour l'instant.
#[allow(dead_code)]
fn _hash_topic(s: &str) -> u64 {
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}
