//! Erreurs de la couche d'état natif.

use sango_primitives::NativeAddress;
use thiserror::Error;

/// Erreur produite lors d'une mutation d'état natif.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum StateError {
    /// Solde insuffisant pour un débit.
    #[error("insufficient balance for {address}: requested {requested}, available {available}")]
    InsufficientBalance {
        /// Adresse débitée.
        address: NativeAddress,
        /// Montant demandé (base units).
        requested: u128,
        /// Solde disponible (base units).
        available: u128,
    },

    /// Un crédit ferait dépasser `u128::MAX`.
    #[error("balance overflow for {address}")]
    BalanceOverflow {
        /// Adresse créditée.
        address: NativeAddress,
    },

    /// Un `bump_nonce` ferait dépasser `u64::MAX`.
    #[error("nonce overflow for {address}")]
    NonceOverflow {
        /// Adresse concernée.
        address: NativeAddress,
    },
}
