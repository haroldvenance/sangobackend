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
