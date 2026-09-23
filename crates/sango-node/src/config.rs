//! Chargement du Genesis et de la configuration du nœud.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use sango_crypto::{derive_native_address, NativeKeypair};
use sango_primitives::{Amount, ChainId32, NativeAddress, PublicKey};
use sango_types::{staking_params, NativeAccount, ValidatorInfo};

/// Erreur produite au chargement de la config.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Erreur d'I/O.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// Erreur de parsing JSON.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    /// Champ invalide.
    #[error("invalid {field}: {reason}")]
    Invalid {
        /// Champ fautif.
        field: &'static str,
        /// Raison.
        reason: String,
    },
}

/// Format JSON d'un Genesis de devnet/testnet.
///
/// Tous les montants sont en SANGO (chaîne décimale, ex. `"100000"`).
/// Toutes les valeurs binaires sont en hexadécimal sans préfixe `0x`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Chain ID natif, 32 bytes hex.
    pub chain_id_hex: String,
    /// Offre initiale en SANGO (ex. `"1000000000"`).
    pub initial_supply_sango: String,
    /// Active la distribution PoS.
    #[serde(default)]
    pub rewards_enabled: bool,
    /// Seed du validateur local (32 bytes hex), si ce nœud est validateur.
    #[serde(default)]
    pub self_validator_seed_hex: Option<String>,
    /// Tous les validateurs du réseau (y compris le nœud local).
    #[serde(default)]
    pub validators: Vec<ValidatorEntry>,
    /// Allocations initiales.
    #[serde(default)]
    pub allocations: Vec<AllocationEntry>,
}

/// Entrée validateur.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorEntry {
    /// Seed Ed25519 (32 bytes hex).
    pub seed_hex: String,
    /// Voting power en SANGO.
    pub voting_power_sango: String,
    /// Commission en basis points. Défaut : 700 (7 %).
    #[serde(default = "default_commission_bps")]
    pub commission_bps: u32,
}

fn default_commission_bps() -> u32 {
    700
}

/// Entrée d'allocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllocationEntry {
    /// Adresse native (20 bytes hex).
    pub address_hex: String,
    /// Montant en SANGO.
    pub amount_sango: String,
    /// Clé publique Ed25519 (32 bytes hex), si le compte doit être actif.
    #[serde(default)]
    pub public_key_hex: Option<String>,
}

/// Genesis résolu, prêt à être appliqué au state.
#[derive(Debug)]
pub struct RuntimeGenesis {
    /// Chain ID.
    pub chain_id: ChainId32,
    /// Offre initiale.
    pub initial_supply: Amount,
    /// Récompenses PoS activées.
    pub rewards_enabled: bool,
    /// Comptes initiaux.
    pub accounts: Vec<NativeAccount>,
    /// Validateurs initiaux.
    pub validators: Vec<ValidatorInfo>,
    /// Keypair du validateur local (None si nœud non-validateur).
    pub local_keypair: Option<NativeKeypair>,
}

impl RuntimeGenesis {
    /// Charge un RuntimeGenesis depuis un fichier JSON.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let bytes = fs::read(path)?;
        let cfg: NodeConfig = serde_json::from_slice(&bytes)?;
        Self::from_config(cfg)
    }

    /// Résout une config JSON en types runtime.
    pub fn from_config(cfg: NodeConfig) -> Result<Self, ConfigError> {
        // chain_id.
        let chain_id_bytes = hex::decode(&cfg.chain_id_hex).map_err(|e| ConfigError::Invalid {
            field: "chain_id_hex",
            reason: e.to_string(),
        })?;
        if chain_id_bytes.len() != 32 {
            return Err(ConfigError::Invalid {
                field: "chain_id_hex",
                reason: format!("expected 32 bytes, got {}", chain_id_bytes.len()),
            });
        }
        let mut cid = [0u8; 32];
        cid.copy_from_slice(&chain_id_bytes);
        let chain_id = ChainId32::from_bytes(cid);

        // Initial supply.
        let initial_supply = parse_sango(&cfg.initial_supply_sango, "initial_supply_sango")?;

        // Validators.
        let mut validators = Vec::with_capacity(cfg.validators.len());
        let mut local_keypair = None;
        for (i, v) in cfg.validators.iter().enumerate() {
            let seed = hex::decode(&v.seed_hex).map_err(|e| ConfigError::Invalid {
                field: "validators.seed_hex",
                reason: format!("[{i}]: {e}"),
            })?;
            if seed.len() != 32 {
                return Err(ConfigError::Invalid {
                    field: "validators.seed_hex",
                    reason: format!("[{i}]: expected 32 bytes, got {}", seed.len()),
                });
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&seed);
            let kp = NativeKeypair::from_seed(arr);
            let pk = kp.public_key();
            let address = derive_native_address(&pk);
            let self_stake = parse_sango(&v.voting_power_sango, "voting_power_sango")?;
            if v.commission_bps > staking_params::MAX_COMMISSION_BPS {
                return Err(ConfigError::Invalid {
                    field: "commission_bps",
                    reason: format!("[{i}]: {} > max", v.commission_bps),
                });
            }
            validators.push(ValidatorInfo {
                address,
                public_key: pk,
                self_stake,
                total_delegated: Amount::ZERO,
                commission_bps: v.commission_bps,
                pending_commission_bps: None,
                pending_commission_at: None,
                jailed: false,
                jailed_until: None,
                downtime_window_start: 0,
                downtime_missed: 0,
            });
            // Est-ce le validateur local ?
            if let Some(self_seed_hex) = &cfg.self_validator_seed_hex {
                if &v.seed_hex == self_seed_hex {
                    local_keypair = Some(NativeKeypair::from_seed(arr));
                }
            }
        }

        // Allocations.
        let mut accounts = Vec::with_capacity(cfg.allocations.len());
        for (i, a) in cfg.allocations.iter().enumerate() {
            let address = parse_address(&a.address_hex, i)?;
            let balance = parse_sango(&a.amount_sango, "amount_sango")?;
            let public_key = match &a.public_key_hex {
                Some(pk_hex) => {
                    let bytes = hex::decode(pk_hex).map_err(|e| ConfigError::Invalid {
                        field: "public_key_hex",
                        reason: format!("[{i}]: {e}"),
                    })?;
                    if bytes.len() != 32 {
                        return Err(ConfigError::Invalid {
                            field: "public_key_hex",
                            reason: format!("[{i}]: expected 32 bytes"),
                        });
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    PublicKey::from_bytes(arr)
                }
                None => PublicKey::ZERO,
            };
            // Vérifier la cohérence adresse ↔ clé publique si fournie.
            if !public_key.is_zero() {
                let derived = derive_native_address(&public_key);
                if derived != address {
                    return Err(ConfigError::Invalid {
                        field: "public_key_hex",
                        reason: format!("[{i}]: does not derive to address 0x{}", a.address_hex),
                    });
                }
            }
            accounts.push(NativeAccount {
                address,
                public_key,
                balance,
                nonce: 0,
            });
        }

        Ok(Self {
            chain_id,
            initial_supply,
            rewards_enabled: cfg.rewards_enabled,
            accounts,
            validators,
            local_keypair,
        })
    }
}

fn parse_sango(s: &str, field: &'static str) -> Result<Amount, ConfigError> {
    let n: u128 = s.parse().map_err(|e| ConfigError::Invalid {
        field,
        reason: format!("{e}"),
    })?;
    Amount::from_sango(n).ok_or(ConfigError::Invalid {
        field,
        reason: "overflow".into(),
    })
}

fn parse_address(s: &str, i: usize) -> Result<NativeAddress, ConfigError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| ConfigError::Invalid {
        field: "address_hex",
        reason: format!("[{i}]: {e}"),
    })?;
    if bytes.len() != 20 {
        return Err(ConfigError::Invalid {
            field: "address_hex",
            reason: format!("[{i}]: expected 20 bytes, got {}", bytes.len()),
        });
    }
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&bytes);
    Ok(NativeAddress::from_bytes(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_json() -> String {
        r#"{
            "chain_id_hex": "1111111111111111111111111111111111111111111111111111111111111111",
            "initial_supply_sango": "1000000000",
            "rewards_enabled": true,
            "self_validator_seed_hex": "0101010101010101010101010101010101010101010101010101010101010101",
            "validators": [
                {
                    "seed_hex": "0101010101010101010101010101010101010101010101010101010101010101",
                    "voting_power_sango": "100000"
                }
            ],
            "allocations": [
                {
                    "address_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "amount_sango": "100000000"
                }
            ]
        }"#
        .into()
    }

    #[test]
    fn load_config_ok() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(&path, sample_json()).unwrap();
        let g = RuntimeGenesis::load(&path).unwrap();
        assert!(g.rewards_enabled);
        assert_eq!(g.validators.len(), 1);
        assert_eq!(g.accounts.len(), 1);
        assert!(g.local_keypair.is_some());
        assert_eq!(g.initial_supply, Amount::from_sango(1_000_000_000).unwrap());
    }

    #[test]
    fn reject_bad_chain_id_length() {
        let json = sample_json().replace(
            "1111111111111111111111111111111111111111111111111111111111111111",
            "11",
        );
        let cfg: NodeConfig = serde_json::from_str(&json).unwrap();
        let err = RuntimeGenesis::from_config(cfg).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                field: "chain_id_hex",
                ..
            }
        ));
    }

    #[test]
    fn reject_invalid_commission() {
        let json = sample_json().replace(
            r#""voting_power_sango": "100000""#,
            r#""voting_power_sango": "100000", "commission_bps": 5000"#,
        );
        let cfg: NodeConfig = serde_json::from_str(&json).unwrap();
        let err = RuntimeGenesis::from_config(cfg).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                field: "commission_bps",
                ..
            }
        ));
    }

    #[test]
    fn reject_pubkey_address_mismatch() {
        let json = sample_json().replace(
            r#""address_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","#,
            r#""address_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "public_key_hex": "0202020202020202020202020202020202020202020202020202020202020202","#,
        );
        let cfg: NodeConfig = serde_json::from_str(&json).unwrap();
        let err = RuntimeGenesis::from_config(cfg).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                field: "public_key_hex",
                ..
            }
        ));
    }
}
