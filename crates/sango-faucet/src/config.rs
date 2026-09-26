//! Configuration du faucet (fichier JSON).
//!
//! ## Format
//!
//! ```json
//! {
//!   "rpc_url": "http://127.0.0.1:8545",
//!   "listen_addr": "0.0.0.0:3000",
//!   "faucet_seed_hex": "aa...32 bytes",
//!   "amount_sango": "100",
//!   "cooldown_secs": 3600,
//!   "max_requests_per_ip": 5,
//!   "max_fee_base_units": 1000
//! }
//! ```
//!
//! Seuls `rpc_url`, `listen_addr` et `faucet_seed_hex` sont obligatoires.
//! Les autres champs ont des valeurs par défaut raisonnables.

use std::fs;
use std::net::SocketAddr;
use std::path::Path;

use serde::Deserialize;
use thiserror::Error;

use sango_crypto::NativeKeypair;
use sango_primitives::Amount;

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
struct FaucetConfigFile {
    rpc_url: String,
    listen_addr: String,
    faucet_seed_hex: String,
    #[serde(default = "default_amount")]
    amount_sango: String,
    #[serde(default = "default_cooldown")]
    cooldown_secs: u64,
    #[serde(default = "default_max_per_ip")]
    max_requests_per_ip: u32,
    #[serde(default = "default_max_fee")]
    max_fee_base_units: u64,
}

fn default_amount() -> String {
    "100".into()
}
fn default_cooldown() -> u64 {
    3600
}
fn default_max_per_ip() -> u32 {
    5
}
fn default_max_fee() -> u64 {
    1000
}

/// Configuration résolue du faucet.
///
/// N'expose **jamais** la clé privée via `Debug` : l'implémentation
/// manuelle masque `faucet_keypair`.
pub struct Config {
    /// URL du nœud RPC (`http://host:port` ou `https://host:port`).
    pub rpc_url: String,
    /// Adresse d'écoute HTTP du faucet.
    pub listen_addr: SocketAddr,
    /// Keypair Ed25519 du faucet (celle qui signe les txs).
    pub faucet_keypair: NativeKeypair,
    /// Montant envoyé par drip (base units).
    pub amount_base_units: u128,
    /// Cooldown par adresse (secondes).
    pub cooldown_secs: u64,
    /// Nombre max de drips par IP sur `cooldown_secs`.
    pub max_requests_per_ip: u32,
    /// `max_fee` des txs faucet (base units/gas).
    pub max_fee_base_units: u128,
}

impl Config {
    /// Charge une config depuis un fichier JSON.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let bytes = fs::read(path)?;
        let file: FaucetConfigFile = serde_json::from_slice(&bytes)?;
        Self::from_file(file)
    }

    fn from_file(file: FaucetConfigFile) -> Result<Self, ConfigError> {
        let listen_addr: SocketAddr =
            file.listen_addr.parse().map_err(|e| ConfigError::Invalid {
                field: "listen_addr",
                reason: format!("{e}"),
            })?;

        let seed_bytes = hex::decode(&file.faucet_seed_hex).map_err(|e| ConfigError::Invalid {
            field: "faucet_seed_hex",
            reason: format!("{e}"),
        })?;
        if seed_bytes.len() != 32 {
            return Err(ConfigError::Invalid {
                field: "faucet_seed_hex",
                reason: format!("expected 32 bytes, got {}", seed_bytes.len()),
            });
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);
        let faucet_keypair = NativeKeypair::from_seed(seed);

        let amount_sango: u128 = file
            .amount_sango
            .parse()
            .map_err(|e| ConfigError::Invalid {
                field: "amount_sango",
                reason: format!("{e}"),
            })?;
        let amount = Amount::from_sango(amount_sango).ok_or(ConfigError::Invalid {
            field: "amount_sango",
            reason: "overflow".into(),
        })?;

        Ok(Self {
            rpc_url: file.rpc_url,
            listen_addr,
            faucet_keypair,
            amount_base_units: amount.base_units(),
            cooldown_secs: file.cooldown_secs,
            max_requests_per_ip: file.max_requests_per_ip,
            max_fee_base_units: file.max_fee_base_units as u128,
        })
    }
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("rpc_url", &self.rpc_url)
            .field("listen_addr", &self.listen_addr)
            .field("faucet_keypair", &"<redacted>")
            .field("amount_base_units", &self.amount_base_units)
            .field("cooldown_secs", &self.cooldown_secs)
            .field("max_requests_per_ip", &self.max_requests_per_ip)
            .field("max_fee_base_units", &self.max_fee_base_units)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_json() -> String {
        r#"{
            "rpc_url": "http://127.0.0.1:8545",
            "listen_addr": "127.0.0.1:3000",
            "faucet_seed_hex": "aaaa...aaaa"
        }"#
        .replace("aaaa...aaaa", &"aa".repeat(32))
    }

    #[test]
    fn load_valid() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("faucet.json");
        std::fs::write(&p, sample_json()).unwrap();
        let cfg = Config::load(&p).unwrap();
        assert_eq!(cfg.rpc_url, "http://127.0.0.1:8545");
        assert_eq!(cfg.amount_base_units, 100 * 10_000_000);
        assert_eq!(cfg.cooldown_secs, 3600);
        assert_eq!(cfg.max_requests_per_ip, 5);
    }

    #[test]
    fn reject_bad_seed() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("faucet.json");
        std::fs::write(&p, sample_json().replace(&"aa".repeat(32), "aabb")).unwrap();
        let err = Config::load(&p).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                field: "faucet_seed_hex",
                ..
            }
        ));
    }

    #[test]
    fn reject_bad_listen() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("faucet.json");
        std::fs::write(&p, sample_json().replace("127.0.0.1:3000", "not-an-addr")).unwrap();
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
