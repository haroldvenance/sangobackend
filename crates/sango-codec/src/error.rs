//! Erreurs du codec canonique.

use thiserror::Error;

/// Erreur produite par [`super::Encoder`] ou [`super::Decoder`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CodecError {
    /// L'entrée est trop courte pour lire la quantité demandée.
    #[error("unexpected end of input: needed {needed} byte(s) at position {position}, only {remaining} left")]
    UnexpectedEof {
        /// Position de lecture courante.
        position: usize,
        /// Nombre de bytes demandés.
        needed: usize,
        /// Bytes encore disponibles.
        remaining: usize,
    },

    /// Bytes résiduels après la fin du décodage attendu.
    #[error("trailing bytes: {count} unexpected byte(s) at position {position}")]
    TrailingBytes {
        /// Position après décodage.
        position: usize,
        /// Nombre de bytes restants.
        count: usize,
    },

    /// Un préfixe de longueur annonce plus de bytes que l'entrée n'en contient.
    #[error("invalid length prefix: declared {declared}, but only {remaining} byte(s) remain")]
    InvalidLength {
        /// Longueur déclarée.
        declared: u64,
        /// Bytes réellement disponibles.
        remaining: usize,
    },

    /// Tag inconnu dans une énumération.
    #[error("invalid tag: {tag}")]
    InvalidTag {
        /// Tag lu.
        tag: u8,
    },

    /// Le payload d'un variant est malformé (ex. typed-tx EVM invalide).
    #[error("malformed payload: {reason}")]
    MalformedPayload {
        /// Raison courte (statique).
        reason: &'static str,
    },
}
