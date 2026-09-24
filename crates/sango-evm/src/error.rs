//! Erreurs du stockage EVM.

use thiserror::Error;

/// Erreur produite par le stockage EVM / MPT.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EvmError {
    /// Payload RLP mal formé (longueur, item count, etc.).
    #[error("malformed RLP payload")]
    MalformedRlp,

    /// Un entier dépasse sa taille maximale pendant le décodage.
    #[error("integer overflow while decoding field: {field}")]
    IntegerOverflow {
        /// Nom du champ fautif.
        field: &'static str,
    },

    /// Un compte encodé doit être une liste RLP de 4 items.
    #[error("invalid account RLP: expected list of 4 items")]
    InvalidAccountRlp,

    /// Un hash (storage_root, code_hash) doit faire exactement 32 bytes.
    #[error("invalid 32-byte hash in account RLP")]
    InvalidHashLength,

    /// Un slot de stockage doit faire exactement 32 bytes.
    #[error("storage slot must be exactly 32 bytes")]
    InvalidSlotLength,

    /// Le hash du bytecode ne correspond pas au `code_hash` annoncé.
    ///
    /// Invariant Ethereum : `code_hash = Keccak256(bytecode)`. Une entrée
    /// qui viole cet invariant doit être rejetée.
    #[error("code hash mismatch: expected {expected}, computed {computed}")]
    CodeHashMismatch {
        /// Hash attendu (clé de lookup).
        expected: sango_primitives::Hash32,
        /// Hash recalculé depuis le bytecode.
        computed: sango_primitives::Hash32,
    },

    /// Le bytecode demandé n'est pas présent dans le stockage de code.
    #[error("code not found for code_hash {code_hash}")]
    CodeNotFound {
        /// Hash du code recherché.
        code_hash: sango_primitives::Hash32,
    },

    /// Erreur provenant de revm (formattée).
    #[error("revm: {0}")]
    Revm(String),
}
