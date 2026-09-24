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
    /// n'existe pas dans l'état.
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

    /// Le cumul `total_burned` dépasserait `u128::MAX`.
    #[error("total_burned overflow: current {current}, delta {delta}")]
    TotalBurnedOverflow {
        /// Valeur actuelle.
        current: u128,
        /// Delta tenté.
        delta: u128,
    },

    /// Le cumul `total_gas_used` dépasserait `u64::MAX`.
    #[error("total_gas_used overflow: current {current}, delta {delta}")]
    TotalGasUsedOverflow {
        /// Valeur actuelle.
        current: u64,
        /// Delta tenté.
        delta: u64,
    },

    /// Une métadonnée présente dans l'état n'a pas pu être décodée
    /// (encodage corrompu ou incompatible).
    #[error("corrupted metadata entry: {key}")]
    CorruptedMetadata {
        /// Nom de la clé fautive.
        key: &'static str,
    },

    /// Le compteur `next_unbonding_id` a atteint `u64::MAX`.
    ///
    /// Cas purement théorique (impossible à atteindre avec des ressources
    /// physiques bornées) mais vérifié par prudence.
    #[error("next_unbonding_id overflow")]
    UnbondingIdOverflow,
}
