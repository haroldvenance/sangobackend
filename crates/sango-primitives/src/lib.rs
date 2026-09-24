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
//! - clés et signatures : [`PublicKey`], [`Signature`]
//! - entiers EVM : [`U256`]
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
mod keys;
mod numeric;

pub use address::{EvmAddress, NativeAddress};
pub use amount::{Amount, BASE_UNITS_PER_SANGO, MAX_SUPPLY_BASE};
pub use chain_id::{ChainId32, EvmChainId};
pub use error::PrimitiveError;
pub use hash::Hash32;
pub use keys::{PublicKey, Signature};
pub use numeric::{Epoch, Height, Round};

/// Entier non signé de 256 bits, base de tous les calculs EVM.
///
/// Alias vers [`ruint::Uint<256, 4>`] — le **même** type que celui utilisé
/// par `revm` et `alloy-primitives`. Cela garantit qu'à l'étape 4c, les
/// valeurs EVM (balances, nonces, gas, etc.) se propagent sans conversion.
///
/// ## Représentation
///
/// - **En mémoire** : 4 × `u64` little-endian (layout `ruint`).
/// - **En RLP** (Ethereum) : byte string big-endian à longueur variable,
///   les zéros de tête étant retirés.
/// - **En Sango-codec** : 32 bytes big-endian fixes (voir
///   `sango_codec::impls::U256`).
pub type U256 = ruint::Uint<256, 4>;

/// Réexport direct de [`ruint::Uint`] pour les cas génériques.
pub use ruint::Uint;
