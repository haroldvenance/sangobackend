//! `sango-primitives` — types fondamentaux du protocole Sango V1.
//!
//! Ce crate ne contient **aucune logique métier complexe**. Il fournit
//! uniquement les types de base utilisés par le reste du workspace :
//!
//! - hashes : [`Hash32`]
//! - identifiants réseau : [`ChainId32`], [`EvmChainId`]
//! - adresses : [`NativeAddress`], [`EvmAddress`]
//! - numériques : [`Height`], [`Round`], [`Epoch`]
//! - montants : [`Amount`]
//!
//! Voir `SANGO PROTOCOL FREEZE V1` pour les règles normatives.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod address;
mod amount;
mod bytes;
mod chain_id;
mod error;
mod hash;
mod numeric;

pub use address::{EvmAddress, NativeAddress};
pub use amount::{Amount, BASE_UNITS_PER_SANGO, MAX_SUPPLY_BASE};
pub use chain_id::{ChainId32, EvmChainId};
pub use error::PrimitiveError;
pub use hash::Hash32;
pub use numeric::{Epoch, Height, Round};
