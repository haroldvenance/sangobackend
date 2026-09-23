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
//! ## Ce que ce crate **ne fait pas**
//!
//! - La logique de consensus.
//! - La validation des messages (le [`crate::P2pService`] transmet le
//!   message décodé au driver, qui valide).
//! - La synchronisation initiale (à venir : protocole `sync` séparé).
//!
//! ## Invariants
//!
//! - Le `PeerId` libp2p est **distinct** de l'identité du validateur.
//! - Un message est diffusé uniquement après décodage réussi côté émetteur.
//! - Un message reçu n'est **jamais** relayé sans validation par le
//!   driver (via `P2pService::broadcast`).

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
pub use service::{spawn, spawn_with_events, P2pCommand, P2pEvent, P2pHandle, P2pService};
