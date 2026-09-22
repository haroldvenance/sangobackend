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

    /// Tentative d'enregistrer une clé publique sur une adresse qui
    /// n'existe pas dans l'état (même pas comme « fantôme »).
    #[error("account not found: {address}")]
    AccountNotFound {
        /// Adresse concernée.
        address: NativeAddress,
    },

    /// Tentative d'enregistrer une clé publique sur un compte qui en a
    /// déjà une. La rotation de clé n'est **pas** autorisée en V1.
    #[error("public key already registered for {address}")]
    PublicKeyAlreadyRegistered {
        /// Adresse concernée.
        address: NativeAddress,
    },

    /// La clé publique fournie est `PublicKey::ZERO`.
    #[error("public key must not be PublicKey::ZERO")]
    PublicKeyIsZero,

    /// La clé publique fournie ne dérive pas vers l'adresse cible.
    #[error("public key does not derive to address {address}")]
    PublicKeyDoesNotMatchAddress {
        /// Adresse cible.
        address: NativeAddress,
    },
}
