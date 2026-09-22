//! Erreurs spécifiques aux structures composites de Sango.

use thiserror::Error;

/// Erreur produite lors de la validation d'une structure de protocole.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TypeError {
    /// Un champ ne respecte pas une contrainte normative.
    #[error("invalid {field}: {reason}")]
    InvalidField {
        /// Nom du champ fautif.
        field: &'static str,
        /// Raison du rejet.
        reason: String,
    },

    /// Une signature native ne vérifie pas.
    #[error("signature verification failed")]
    SignatureVerificationFailed,

    /// Somme des allocations != initial_supply.
    #[error("allocation sum mismatch: expected {expected}, got {actual}")]
    AllocationSumMismatch {
        /// `initial_supply` déclaré.
        expected: u128,
        /// Somme réellement calculée.
        actual: u128,
    },
}
