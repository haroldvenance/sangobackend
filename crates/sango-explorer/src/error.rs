//! Erreurs de l'explorer.

use sango_wallet::WalletError;
use thiserror::Error;

/// Erreur produite par l'explorer.
#[derive(Debug, Error)]
pub enum ExplorerError {
    /// Erreur du client RPC.
    #[error("rpc: {0}")]
    Rpc(#[from] WalletError),

    /// Erreur de parsing d'une réponse RPC.
    #[error("parse: {0}")]
    Parse(String),

    /// Erreur de config.
    #[error("config: {0}")]
    Config(#[from] crate::config::ConfigError),

    /// Erreur d'I/O.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}
