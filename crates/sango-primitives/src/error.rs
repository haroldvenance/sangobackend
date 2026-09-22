//! Erreurs de bas niveau pour les types primitifs.

use thiserror::Error;

/// Erreur produite par un type primitif lors de la construction ou du parsing.
#[derive(Debug, Error)]
pub enum PrimitiveError {
    /// La longueur d'un tableau de bytes ne correspond pas à la longueur attendue.
    #[error("invalid length: expected {expected}, got {actual}")]
    InvalidLength {
        /// Longueur attendue.
        expected: usize,
        /// Longueur réellement fournie.
        actual: usize,
    },

    /// La chaîne hexadécimale fournie n'est pas valide.
    #[error("invalid hex: {0}")]
    InvalidHex(String),
}
