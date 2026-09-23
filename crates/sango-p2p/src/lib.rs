//! `sango-p2p` — couche réseau pair-à-pair de Sango V1.
//!
//! ## Architecture
//!
//! - **Transport** : QUIC (TLS intégré, multiplexage natif).
//! - **Propagation** : gossipsub pour les propositions, votes, transactions
//!   et blocs.
//! - **Découverte** : mDNS (devnet/testnet local) + bootstrap statique.
//! - **Liveness** : ping.
//! - **Encodage** : codec canonique Sango, aucun protobuf.
//!
//! ## Utilisation depuis un thread synchrone
//!
//! ```no_run
//! use sango_p2p::{spawn, P2pConfig, NetworkMessage};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Le runtime tokio doit exister (créé une fois dans le binaire).
//! let rt = tokio::runtime::Runtime::new()?;
//! let _guard = rt.enter();
//!
//! let handle = spawn(P2pConfig::devnet())?;
//!
//! // Boucle du driver : non-bloquante.
//! if let Some(event) = handle.service.try_recv_event() {
//!     println!("event: {event:?}");
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Invariants
//!
//! - Le `PeerId` libp2p est **distinct** de l'identité du validateur.
//! - Un message reçu n'est **jamais** relayé sans validation par le driver.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod config;
mod error;
mod message;
mod service;
pub mod topics;

pub use config::P2pConfig;
pub use error::P2pError;
pub use message::{MessageType, NetworkMessage};
pub use service::{spawn, P2pCommand, P2pEvent, P2pHandle, P2pService, CHANNEL_CAPACITY};

// Ré-exports de libp2p pour éviter que les consommateurs (sango-node)
// n'aient à dépendre directement de libp2p.
pub use libp2p::multiaddr;
pub use libp2p::{Multiaddr, PeerId};
