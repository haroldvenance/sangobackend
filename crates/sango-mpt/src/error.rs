//! Erreurs du MPT Ethereum-compatible.

use thiserror::Error;

/// Erreur produite par le MPT.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MptError {
    /// Un nœud RLP est mal formé (structure invalide).
    #[error("malformed MPT node")]
    MalformedNode,

    /// Un chemin hex-prefix est invalide (nibble ou flag inattendu).
    #[error("invalid hex-prefix path")]
    InvalidHexPrefix,

    /// Un pointeur d'enfant référence un hash attendu mais absent du proof.
    #[error("proof too short: missing child node")]
    ProofTooShort,

    /// Un hash de nœud ne correspond pas à celui référencé par le parent.
    #[error("hash mismatch: proof node does not match parent reference")]
    HashMismatch,

    /// Un nœud inline ne correspond pas exactement aux bytes référencés.
    #[error("inline node reference mismatch")]
    InlineRefMismatch,

    /// Un proof vide a été fourni alors que la racine n'est pas l'arbre vide.
    #[error("empty proof for non-empty root")]
    EmptyProof,
}
