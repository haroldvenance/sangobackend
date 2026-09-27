//! Configuration de l'explorer (fichier JSON).
//!
//! ## Format
//!
//! ```json
//! {
//!   "rpc_url": "http://127.0.0.1:8545",
//!   "listen_addr": "127.0.0.1:8080",
//!   "network_name": "Sango Devnet"
//! }
//! ```

use std::fs;
use std::net::SocketAddr;
use std::path::Path;

use serde::Deserialize;
use thiserror::Error;

/// Erreur produite au chargement de la config.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Erreur d'I/O.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Erreur JSON.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// Champ invalide.
    #[error("invalid {field}: {reason}")]
    Invalid {
        /// Nom du champ.
        field: &'static str,
        /// Raison.
        reason: String,
    },
}

#[derive(Debug, Deserialize)]
struct ExplorerConfigFile {
    rpc_url: String,
    listen_addr: String,
    #[serde(default = "default_network_name")]
    network_name: String,
}

fn default_network_name() -> String {
    "Sango".into()
}

/// Configuration résolue de l'explorer.
#[derive(Debug, Clone)]
pub struct Config {
    /// URL du nœud RPC (http://… ou https://…).
    pub rpc_url: String,
    /// Adresse d'écoute HTTP de l'explorer.
    pub listen_addr: SocketAddr,
    /// Nom affiché dans le header (ex. « Sango Devnet »).
    pub network_name: String,
}

impl Config {
    /// Charge une config depuis un fichier JSON.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let bytes = fs::read(path)?;
        let file: ExplorerConfigFile = serde_json::from_slice(&bytes)?;
        Self::from_file(file)
    }

    fn from_file(file: ExplorerConfigFile) -> Result<Self, ConfigError> {
        let listen_addr: SocketAddr =
            file.listen_addr.parse().map_err(|e| ConfigError::Invalid {
                field: "listen_addr",
                reason: format!("{e}"),
            })?;
        Ok(Self {
            rpc_url: file.rpc_url,
            listen_addr,
            network_name: file.network_name,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> String {
        r#"{
            "rpc_url": "http://127.0.0.1:8545",
            "listen_addr": "127.0.0.1:8080"
        }"#
        .to_string()
    }

    #[test]
    fn load_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("explorer.json");
        std::fs::write(&p, sample()).unwrap();
        let cfg = Config::load(&p).unwrap();
        assert_eq!(cfg.rpc_url, "http://127.0.0.1:8545");
        assert_eq!(cfg.network_name, "Sango");
    }

    #[test]
    fn reject_bad_listen() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("explorer.json");
        std::fs::write(&p, sample().replace("127.0.0.1:8080", "nope")).unwrap();
        let err = Config::load(&p).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                field: "listen_addr",
                ..
            }
        ));
    }
}
