//! Service P2P basé sur libp2p.
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────┐    P2pCommand     ┌─────────────────────┐
//! │   Driver     │ ────────────────► │                     │
//! │   (sync)     │                    │   P2pService        │
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
//! Le service tourne dans une tâche tokio dédiée. Le driver (synchrone)
//! communique avec lui via deux canaux mpsc :
//!
//! - `P2pCommand` : driver → réseau (`broadcast_sync`, `dial`).
//! - `P2pEvent` : réseau → driver (`try_recv_event`, ou `recv_event` async).
//!
//! ## Mode sync
//!
//! Le driver n'a pas besoin d'être async : `broadcast_sync` et
//! `try_recv_event` sont non-bloquants et utilisables depuis un thread
//! classique. `broadcast_sync` échoue si le canal interne est plein
//! (1024 commandes).

use std::sync::{Arc, Mutex};
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

/// Capacité des canaux internes (commandes et événements).
pub const CHANNEL_CAPACITY: usize = 1024;

/// Événement produit par le service P2P.
#[derive(Debug)]
pub enum P2pEvent {
    /// Le swarm a bindé une nouvelle adresse d'écoute.
    NewListenAddr(Multiaddr),
    /// Un peer s'est abonné à un topic.
    Subscribed {
        /// Peer concerné.
        peer_id: PeerId,
        /// Topic (chaîne complète).
        topic: String,
    },
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
    ///
    /// `Box` pour limiter la taille du variant : `NetworkMessage` peut
    /// contenir un `Block` complet (jusqu'à 2 MiB).
    Broadcast(Box<NetworkMessage>),
    /// Se connecter à un peer (adresse + PeerId).
    Dial(Multiaddr),
    /// Arrêter le service.
    Shutdown,
}

/// Handle clonable vers le service P2P.
///
/// Peut être utilisé depuis un thread synchrone (`broadcast_sync`,
/// `try_recv_event`) ou un contexte async (`broadcast`, `dial`).
#[derive(Clone)]
pub struct P2pService {
    cmd_tx: mpsc::Sender<P2pCommand>,
    event_rx: Arc<Mutex<mpsc::Receiver<P2pEvent>>>,
    local_peer_id: PeerId,
}

impl P2pService {
    /// Retourne le `PeerId` local (identité réseau).
    #[must_use]
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// Publie un message (variante async).
    ///
    /// Bloque si le canal interne est plein.
    pub async fn broadcast(&self, message: NetworkMessage) -> Result<(), P2pError> {
        self.cmd_tx
            .send(P2pCommand::Broadcast(Box::new(message)))
            .await
            .map_err(|_| P2pError::ChannelClosed)
    }

    /// Publie un message (variante sync, non-bloquante).
    ///
    /// Utilisée par le driver. Retourne [`P2pError::ChannelFull`] si le
    /// canal interne est plein, ou [`P2pError::ChannelClosed`] si le
    /// service est arrêté.
    pub fn broadcast_sync(&self, message: NetworkMessage) -> Result<(), P2pError> {
        self.cmd_tx
            .try_send(P2pCommand::Broadcast(Box::new(message)))
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => P2pError::ChannelFull,
                mpsc::error::TrySendError::Closed(_) => P2pError::ChannelClosed,
            })
    }

    /// Se connecte à un peer (variante async).
    pub async fn dial(&self, addr: Multiaddr) -> Result<(), P2pError> {
        self.cmd_tx
            .send(P2pCommand::Dial(addr))
            .await
            .map_err(|_| P2pError::ChannelClosed)
    }

    /// Se connecte à un peer (variante sync, non-bloquante).
    pub fn dial_sync(&self, addr: Multiaddr) -> Result<(), P2pError> {
        self.cmd_tx
            .try_send(P2pCommand::Dial(addr))
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => P2pError::ChannelFull,
                mpsc::error::TrySendError::Closed(_) => P2pError::ChannelClosed,
            })
    }

    /// Récupère un événement sans bloquer.
    ///
    /// Retourne `None` si la file est vide.
    pub fn try_recv_event(&self) -> Option<P2pEvent> {
        let mut rx = self.event_rx.lock().expect("event_rx mutex poisoned");
        rx.try_recv().ok()
    }

    /// Demande l'arrêt du service (async).
    pub async fn shutdown(&self) -> Result<(), P2pError> {
        self.cmd_tx
            .send(P2pCommand::Shutdown)
            .await
            .map_err(|_| P2pError::ChannelClosed)
    }

    /// Demande l'arrêt du service (sync, non-bloquant).
    pub fn shutdown_sync(&self) -> Result<(), P2pError> {
        self.cmd_tx
            .try_send(P2pCommand::Shutdown)
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => P2pError::ChannelFull,
                mpsc::error::TrySendError::Closed(_) => P2pError::ChannelClosed,
            })
    }
}

impl std::fmt::Debug for P2pService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P2pService")
            .field("local_peer_id", &self.local_peer_id)
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
    let (cmd_tx, cmd_rx) = mpsc::channel::<P2pCommand>(CHANNEL_CAPACITY);
    let (event_tx, event_rx) = mpsc::channel::<P2pEvent>(CHANNEL_CAPACITY);

    let (swarm, local_peer_id) = build_swarm(&cfg)?;

    let task = tokio::spawn(async move { run_swarm(swarm, cmd_rx, event_tx).await });

    Ok(P2pHandle {
        service: P2pService {
            cmd_tx,
            event_rx: Arc::new(Mutex::new(event_rx)),
            local_peer_id,
        },
        task,
    })
}

// --- Construction du swarm --------------------------------------------------

#[derive(NetworkBehaviour)]
struct SangoBehaviour {
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
    ping: ping::Behaviour,
}

fn build_swarm(cfg: &P2pConfig) -> Result<(Swarm<SangoBehaviour>, PeerId), P2pError> {
    // Identité P2P (Ed25519 par défaut libp2p). Distincte de l'identité
    // validateur.
    let keypair = identity::Keypair::generate_ed25519();

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_quic()
        .with_behaviour(|key| {
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

            let mdns =
                mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())
                    .map_err(|e| P2pError::Config(format!("mdns: {e}")))?;

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
    for addr in &cfg.listen_addrs {
        swarm
            .listen_on(addr.clone())
            .map_err(|e| P2pError::Transport(format!("listen_on {addr}: {e}")))?;
    }

    // Ajouter les peers bootstrap en explicit peers (permet gossipsub de
    // les considérer même s'ils ne sont pas encore connectés).
    for (_addr, peer_id) in &cfg.bootstrap_addrs {
        swarm.behaviour_mut().gossipsub.add_explicit_peer(peer_id);
    }

    let local_peer_id = *swarm.local_peer_id();
    Ok((swarm, local_peer_id))
}

// --- Boucle événementielle --------------------------------------------------

async fn run_swarm(
    mut swarm: Swarm<SangoBehaviour>,
    mut cmd_rx: mpsc::Receiver<P2pCommand>,
    event_tx: mpsc::Sender<P2pEvent>,
) -> Result<(), P2pError> {
    loop {
        tokio::select! {
            // --- Commandes entrantes -----------------------------------------
            cmd = cmd_rx.recv() => {
                match cmd {
                    None | Some(P2pCommand::Shutdown) => return Ok(()),
                    Some(P2pCommand::Dial(addr)) => {
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
                        let _ = event_tx.send(P2pEvent::NewListenAddr(address)).await;
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
                                    format!("decode from {propagation_source}: {e}")
                                )).await;
                            }
                        }
                    }
                    SwarmEvent::Behaviour(SangoBehaviourEvent::Gossipsub(
                        gossipsub::Event::Subscribed { peer_id, topic }
                    )) => {
                        let _ = event_tx.send(P2pEvent::Subscribed {
                            peer_id,
                            topic: topic.to_string(),
                        }).await;
                    }
                    _ => { /* ignorer les autres événements */ }
                }
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
