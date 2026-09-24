//! Erreurs du mempool.

use sango_primitives::{Hash32, NativeAddress};
use thiserror::Error;

/// Erreur produite lors d'une opération sur le mempool.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MempoolError {
    /// Le mempool a atteint sa capacité maximale.
    #[error("mempool is full")]
    Full,

    /// Transaction déjà présente (même hash).
    #[error("duplicate transaction: {0}")]
    Duplicate(Hash32),

    /// Le nonce est trop ancien (déjà appliqué).
    #[error("nonce too low: expected >= {expected}, got {got}")]
    NonceTooLow {
        /// Nonce attendu minimum.
        expected: u64,
        /// Nonce reçu.
        got: u64,
    },

    /// Le nonce dépasse la fenêtre autorisée (trop en avance).
    #[error("nonce too high: expected <= {expected}, got {got}")]
    NonceTooHigh {
        /// Nonce maximum autorisé.
        expected: u64,
        /// Nonce reçu.
        got: u64,
    },

    /// Nonce déjà occupé par une autre transaction du même émetteur.
    #[error("nonce occupied by {existing} for {address}")]
    NonceOccupied {
        /// Adresse du sender.
        address: NativeAddress,
        /// Hash de la transaction occupant ce nonce.
        existing: Hash32,
    },

    /// Remplacement refusé : le bump de frais est insuffisant.
    #[error("replacement fee too low: need >= {needed}, got {got}")]
    ReplacementFeeTooLow {
        /// Prix effectif minimum requis.
        needed: u128,
        /// Prix effectif fourni.
        got: u128,
    },

    /// `max_fee` inférieur à la base fee courante.
    #[error("max_fee ({max_fee}) below base_fee ({base_fee})")]
    MaxFeeBelowBaseFee {
        /// `max_fee` de la transaction.
        max_fee: u128,
        /// Base fee courante.
        base_fee: u128,
    },
}

/// Erreur produite par le mempool EVM.
///
/// Miroir d'[`MempoolError`] adapté aux types EVM (`EvmAddress`, `U256`).
/// Séparé pour ne pas polluer l'espace des txs natives.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EvmMempoolError {
    /// Le mempool EVM a atteint sa capacité maximale.
    #[error("evm mempool is full")]
    Full,

    /// Transaction déjà présente (même hash).
    #[error("duplicate evm transaction: {0}")]
    Duplicate(Hash32),

    /// Le nonce est trop ancien (déjà appliqué).
    #[error("evm nonce too low: expected >= {expected}, got {got}")]
    NonceTooLow {
        /// Nonce attendu minimum.
        expected: u64,
        /// Nonce reçu.
        got: u64,
    },

    /// Le nonce dépasse la fenêtre autorisée (trop en avance).
    #[error("evm nonce too high: expected <= {expected}, got {got}")]
    NonceTooHigh {
        /// Nonce maximum autorisé.
        expected: u64,
        /// Nonce reçu.
        got: u64,
    },

    /// Nonce déjà occupé par une autre transaction du même émetteur.
    #[error("evm nonce occupied by {existing} for {address}")]
    NonceOccupied {
        /// Adresse EVM du sender.
        address: sango_primitives::EvmAddress,
        /// Hash de la transaction occupant ce nonce.
        existing: Hash32,
    },

    /// Remplacement refusé : le bump de frais est insuffisant.
    #[error("evm replacement fee too low: need >= {needed}, got {got}")]
    ReplacementFeeTooLow {
        /// Priorité effective minimum requise.
        needed: sango_primitives::U256,
        /// Priorité effective fournie.
        got: sango_primitives::U256,
    },

    /// `max_fee_per_gas` inférieur à la base fee courante.
    #[error("evm max_fee_per_gas ({max_fee}) below base_fee ({base_fee})")]
    MaxFeeBelowBaseFee {
        /// `max_fee_per_gas` de la transaction.
        max_fee: sango_primitives::U256,
        /// Base fee courante.
        base_fee: sango_primitives::U256,
    },

    /// La signature secp256k1 n'a pas pu être vérifiée / récupérée.
    #[error("invalid evm signature (cannot recover sender)")]
    InvalidSignature,
}
