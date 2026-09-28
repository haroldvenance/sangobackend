//! Erreurs du wallet.

use thiserror::Error;

use crate::keystore::KeyFileVersion;

/// Erreur produite par une opération du wallet.
#[derive(Debug, Error)]
pub enum WalletError {
    /// Erreur d'I/O (lecture/écriture du keyfile).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// Erreur de (dé)sérialisation.
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),

    /// Erreur de décodage hexadécimal.
    #[error("hex: {0}")]
    Hex(#[from] hex::FromHexError),

    /// Le keyfile existe déjà.
    #[error("keyfile already exists: {0}")]
    KeyfileExists(String),

    /// Le keyfile est introuvable.
    #[error("keyfile not found: {0}")]
    KeyfileNotFound(String),

    /// Le keyfile est corrompu ou versionné différemment.
    #[error("invalid keyfile: {0}")]
    InvalidKeyfile(String),

    /// L'adresse fournie n'est pas valide.
    #[error("invalid address: {0}")]
    InvalidAddress(String),

    /// Le montant fourni n'est pas un décimal valide.
    #[error("invalid amount: {0}")]
    InvalidAmount(String),

    /// Erreur de communication avec le nœud.
    #[error("rpc: {0}")]
    Rpc(String),

    /// Le nœud a retourné une erreur JSON-RPC.
    #[error("rpc error [{code}]: {message}")]
    RpcResponse {
        /// Code JSON-RPC.
        code: i32,
        /// Message.
        message: String,
    },

    /// Usage invalide de la CLI.
    #[error("usage: {0}")]
    Usage(String),

    /// Chaîne attendue en hex mais reçue autre chose.
    #[error("invalid hex string: {0}")]
    InvalidHex(String),

    // --- Chiffrement keyfile -----------------------------------------------
    /// La passphrase fournie est incorrecte (échec de déchiffrement ou MAC).
    #[error("invalid passphrase")]
    InvalidPassphrase,

    /// Le keyfile est déjà chiffré.
    #[error("keyfile is already encrypted")]
    AlreadyEncrypted,

    /// Le keyfile n'est pas chiffré (v1 en clair).
    #[error("keyfile is not encrypted")]
    NotEncrypted,

    /// Erreur Argon2 (paramètres invalides, mémoire insuffisante).
    #[error("argon2: {0}")]
    Argon2(String),

    /// Erreur AEAD (chiffrement / déchiffrement).
    #[error("aead: {0}")]
    Aead(String),

    /// La passphrase est vide (interdit).
    #[error("passphrase must not be empty")]
    EmptyPassphrase,

    /// Le format de keyfile ne supporte pas `--account > 0`.
    ///
    /// Les formats V1 et V2 ne contiennent qu'un seul compte
    /// (la seed elle-même). Seul V3 supporte la dérivation multi-comptes.
    #[error("keyfile format {format:?} contains a single account and does not support --account > 0 (asked for {account})")]
    UnsupportedAccount {
        /// Version du keyfile.
        format: KeyFileVersion,
        /// Index demandé.
        account: u32,
    },
}
