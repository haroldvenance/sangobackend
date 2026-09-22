//! `sango-types` — structures composites du protocole Sango V1.
//!
//! Ce crate définit les objets qui composent l’état et les messages du
//! protocole :
//!
//! - [`BlockHeader`] et son hash canonique ;
//! - [`Transaction`] native et son hash / signature ;
//! - [`Account`] natif ;
//! - [`Genesis`] et ses sous-configurations.
//!
//! Tous les hashes et signatures utilisent :
//!
//! - les domain separators définis dans `sango-crypto::domain` ;
//! - l’encodage canonique fourni par `sango-codec`.
//!
//! Voir `SANGO PROTOCOL FREEZE V1` pour les règles normatives.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod account;
mod error;
mod genesis;
mod header;
mod transaction;

pub use account::Account;
pub use error::TypeError;
pub use genesis::{
    Allocation, ConsensusConfig, EvmConfig, EvmVersion, FeeConfig, Genesis, GenesisValidator,
    LockSchedule,
};
pub use header::BlockHeader;
pub use transaction::{Transaction, TxKind};

/// Version courante du protocole Sango.
pub const PROTOCOL_VERSION_V1: u32 = 1;
