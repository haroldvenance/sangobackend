//! Genesis et structures de configuration V1.

use sango_codec::{CodecError, Decode, Decoder, Encode, Encoder};
use sango_crypto::{domain, keccak256};
use sango_primitives::{Amount, ChainId32, EvmChainId, Hash32, NativeAddress, PublicKey};

use crate::error::TypeError;

/// Version EVM autorisée en V1.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum EvmVersion {
    /// Profil Pectra / Prague.
    Prague,
}

impl EvmVersion {
    /// Tag canonique (`u8`).
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            EvmVersion::Prague => 0x01,
        }
    }

    /// Parse un tag canonique.
    pub fn from_tag(tag: u8) -> Result<Self, CodecError> {
        match tag {
            0x01 => Ok(EvmVersion::Prague),
            other => Err(CodecError::InvalidTag { tag: other }),
        }
    }
}

impl Encode for EvmVersion {
    fn encode(&self, enc: &mut Encoder) {
        enc.write_u8(self.tag());
    }
}

impl Decode for EvmVersion {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Self::from_tag(dec.read_u8()?)
    }
}

/// Configuration consensus.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ConsensusConfig {
    /// Cible de temps de bloc (secondes).
    pub block_time_target: u64,
    /// Longueur d'un epoch (nombre de blocs).
    pub epoch_length: u64,
    /// Nombre maximum de validateurs actifs.
    pub max_active_validators: u32,
    /// Self-stake minimum pour devenir validateur.
    pub minimum_validator_stake: Amount,
    /// Durée d'unbonding (secondes).
    pub unbonding_period: u64,
    /// Slash double-sign en basis points (500 = 5 %).
    pub double_sign_slash_bps: u32,
    /// Seuil de downtime en basis points (8000 = 80 %).
    pub downtime_threshold_bps: u32,
    /// Fenêtre d'observation du downtime (nombre de blocs).
    pub downtime_window: u64,
}

impl Encode for ConsensusConfig {
    fn encode(&self, enc: &mut Encoder) {
        self.block_time_target.encode(enc);
        self.epoch_length.encode(enc);
        self.max_active_validators.encode(enc);
        self.minimum_validator_stake.encode(enc);
        self.unbonding_period.encode(enc);
        self.double_sign_slash_bps.encode(enc);
        self.downtime_threshold_bps.encode(enc);
        self.downtime_window.encode(enc);
    }
}

impl Decode for ConsensusConfig {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            block_time_target: u64::decode(dec)?,
            epoch_length: u64::decode(dec)?,
            max_active_validators: u32::decode(dec)?,
            minimum_validator_stake: Amount::decode(dec)?,
            unbonding_period: u64::decode(dec)?,
            double_sign_slash_bps: u32::decode(dec)?,
            downtime_threshold_bps: u32::decode(dec)?,
            downtime_window: u64::decode(dec)?,
        })
    }
}

/// Configuration du marché des frais.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct FeeConfig {
    /// Base fee initiale (base units par gas).
    pub initial_base_fee: u128,
    /// Ratio cible `gas_used / gas_limit` en basis points (5000 = 50 %).
    pub target_gas_ratio_bps: u32,
    /// Dénominateur de variation maximale de la base fee (8 = 12,5 %/bloc).
    pub max_base_fee_change_denominator: u32,
    /// Part validateur en basis points (9000 = 90 %).
    pub validator_fee_bps: u32,
    /// Part brûlée en basis points (1000 = 10 %).
    pub burn_fee_bps: u32,
}

impl Encode for FeeConfig {
    fn encode(&self, enc: &mut Encoder) {
        self.initial_base_fee.encode(enc);
        self.target_gas_ratio_bps.encode(enc);
        self.max_base_fee_change_denominator.encode(enc);
        self.validator_fee_bps.encode(enc);
        self.burn_fee_bps.encode(enc);
    }
}

impl Decode for FeeConfig {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            initial_base_fee: u128::decode(dec)?,
            target_gas_ratio_bps: u32::decode(dec)?,
            max_base_fee_change_denominator: u32::decode(dec)?,
            validator_fee_bps: u32::decode(dec)?,
            burn_fee_bps: u32::decode(dec)?,
        })
    }
}

/// Configuration EVM.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct EvmConfig {
    /// Version du profil EVM.
    pub evm_version: EvmVersion,
    /// Chain ID natif (32 bytes) — rappelé pour cohérence.
    pub native_chain_id: ChainId32,
    /// Chain ID EVM (`u64`), indépendant du natif.
    pub evm_chain_id: EvmChainId,
    /// Gas limite par bloc.
    pub evm_gas_limit: u64,
    /// Transactions blob (type `0x03`) autorisées.
    pub blob_transactions_enabled: bool,
    /// EIP-7702 autorisé.
    pub eip7702_enabled: bool,
}

impl Encode for EvmConfig {
    fn encode(&self, enc: &mut Encoder) {
        self.evm_version.encode(enc);
        self.native_chain_id.encode(enc);
        self.evm_chain_id.encode(enc);
        self.evm_gas_limit.encode(enc);
        self.blob_transactions_enabled.encode(enc);
        self.eip7702_enabled.encode(enc);
    }
}

impl Decode for EvmConfig {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            evm_version: EvmVersion::decode(dec)?,
            native_chain_id: ChainId32::decode(dec)?,
            evm_chain_id: EvmChainId::decode(dec)?,
            evm_gas_limit: u64::decode(dec)?,
            blob_transactions_enabled: bool::decode(dec)?,
            eip7702_enabled: bool::decode(dec)?,
        })
    }
}

/// Calendrier de verrouillage d'une allocation.
///
/// **Note normative** : le Freeze n'a pas encore spécifié les règles exactes
/// de vesting. Ce type minimal est **provisoire** ; il sera précisé avant
/// Mainnet dans une mise à jour de la spécification.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum LockSchedule {
    /// Aucun verrouillage : disponible immédiatement.
    Unlocked,
    /// Verrouillé jusqu'à un timestamp Unix précis.
    Cliff {
        /// Timestamp Unix de libération (secondes).
        unlock_at: u64,
    },
    /// Libération linéaire entre deux timestamps Unix.
    Linear {
        /// Début de la période de libération.
        start: u64,
        /// Fin de la période de libération.
        end: u64,
    },
}

impl Encode for LockSchedule {
    fn encode(&self, enc: &mut Encoder) {
        match self {
            LockSchedule::Unlocked => enc.write_u8(0x00),
            LockSchedule::Cliff { unlock_at } => {
                enc.write_u8(0x01);
                unlock_at.encode(enc);
            }
            LockSchedule::Linear { start, end } => {
                enc.write_u8(0x02);
                start.encode(enc);
                end.encode(enc);
            }
        }
    }
}

impl Decode for LockSchedule {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let tag = dec.read_u8()?;
        match tag {
            0x00 => Ok(LockSchedule::Unlocked),
            0x01 => Ok(LockSchedule::Cliff {
                unlock_at: u64::decode(dec)?,
            }),
            0x02 => Ok(LockSchedule::Linear {
                start: u64::decode(dec)?,
                end: u64::decode(dec)?,
            }),
            other => Err(CodecError::InvalidTag { tag: other }),
        }
    }
}

/// Allocation native au Genesis.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Allocation {
    /// Adresse native destinataire.
    pub address: NativeAddress,
    /// Montant alloué en base units.
    pub amount: Amount,
    /// Calendrier de verrouillage.
    pub lock_schedule: LockSchedule,
}

impl Encode for Allocation {
    fn encode(&self, enc: &mut Encoder) {
        self.address.encode(enc);
        self.amount.encode(enc);
        self.lock_schedule.encode(enc);
    }
}

impl Decode for Allocation {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            address: NativeAddress::decode(dec)?,
            amount: Amount::decode(dec)?,
            lock_schedule: LockSchedule::decode(dec)?,
        })
    }
}

/// Validateur initial inscrit au Genesis.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct GenesisValidator {
    /// Adresse native du validateur.
    pub address: NativeAddress,
    /// Clé publique Ed25519 du validateur.
    pub public_key: PublicKey,
    /// Self-stake initial.
    pub self_stake: Amount,
    /// Commission en basis points (700 = 7 %).
    pub commission_bps: u32,
}

impl Encode for GenesisValidator {
    fn encode(&self, enc: &mut Encoder) {
        self.address.encode(enc);
        self.public_key.encode(enc);
        self.self_stake.encode(enc);
        self.commission_bps.encode(enc);
    }
}

impl Decode for GenesisValidator {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            address: NativeAddress::decode(dec)?,
            public_key: PublicKey::decode(dec)?,
            self_stake: Amount::decode(dec)?,
            commission_bps: u32::decode(dec)?,
        })
    }
}

/// Genesis Sango V1 (Freeze, section 11).
///
/// Ordre canonique obligatoire :
///
/// ```text
/// version || chain_id || timestamp || initial_supply
/// || consensus_config || fee_config || evm_config
/// || allocations || validators
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Genesis {
    /// Version du format Genesis.
    pub version: u32,
    /// Chain ID natif (32 bytes).
    pub chain_id: ChainId32,
    /// Timestamp Unix de création.
    pub timestamp: u64,
    /// Offre initiale totale (base units).
    pub initial_supply: Amount,
    /// Configuration consensus.
    pub consensus_config: ConsensusConfig,
    /// Configuration des frais.
    pub fee_config: FeeConfig,
    /// Configuration EVM.
    pub evm_config: EvmConfig,
    /// Allocations initiales.
    pub allocations: Vec<Allocation>,
    /// Validateurs Genesis.
    pub validators: Vec<GenesisValidator>,
}

impl Genesis {
    /// Vérifie que `sum(allocations) == initial_supply`.
    pub fn validate(&self) -> Result<(), TypeError> {
        let mut total: u128 = 0;
        for a in &self.allocations {
            total = total.checked_add(a.amount.base_units()).ok_or_else(|| {
                TypeError::InvalidField {
                    field: "allocations",
                    reason: "sum overflows u128".to_string(),
                }
            })?;
        }
        if total != self.initial_supply.base_units() {
            return Err(TypeError::AllocationSumMismatch {
                expected: self.initial_supply.base_units(),
                actual: total,
            });
        }
        Ok(())
    }

    /// Hash canonique :
    ///
    /// ```text
    /// genesis_hash = Keccak256("SANGO/GENESIS/V1" || canonical(genesis))
    /// ```
    #[must_use]
    pub fn hash(&self) -> Hash32 {
        let mut enc = Encoder::new();
        enc.write_raw(domain::GENESIS_V1);
        self.encode(&mut enc);
        keccak256(enc.as_slice())
    }
}

impl Encode for Genesis {
    fn encode(&self, enc: &mut Encoder) {
        self.version.encode(enc);
        self.chain_id.encode(enc);
        self.timestamp.encode(enc);
        self.initial_supply.encode(enc);
        self.consensus_config.encode(enc);
        self.fee_config.encode(enc);
        self.evm_config.encode(enc);
        self.allocations.encode(enc);
        self.validators.encode(enc);
    }
}

impl Decode for Genesis {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            version: u32::decode(dec)?,
            chain_id: ChainId32::decode(dec)?,
            timestamp: u64::decode(dec)?,
            initial_supply: Amount::decode(dec)?,
            consensus_config: ConsensusConfig::decode(dec)?,
            fee_config: FeeConfig::decode(dec)?,
            evm_config: EvmConfig::decode(dec)?,
            allocations: Vec::<Allocation>::decode(dec)?,
            validators: Vec::<GenesisValidator>::decode(dec)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_configs() -> (ConsensusConfig, FeeConfig, EvmConfig) {
        let chain = ChainId32::from_bytes([0x11; 32]);
        (
            ConsensusConfig {
                block_time_target: 5,
                epoch_length: 1000,
                max_active_validators: 100,
                minimum_validator_stake: Amount::from_sango(100_000).unwrap(),
                unbonding_period: 14 * 24 * 3600,
                double_sign_slash_bps: 500,
                downtime_threshold_bps: 8000,
                downtime_window: 100,
            },
            FeeConfig {
                initial_base_fee: 1,
                target_gas_ratio_bps: 5000,
                max_base_fee_change_denominator: 8,
                validator_fee_bps: 9000,
                burn_fee_bps: 1000,
            },
            EvmConfig {
                evm_version: EvmVersion::Prague,
                native_chain_id: chain,
                evm_chain_id: EvmChainId::new(0x53_41_4e_47_4f), // "SANGO" en ASCII
                evm_gas_limit: 30_000_000,
                blob_transactions_enabled: false,
                eip7702_enabled: true,
            },
        )
    }

    fn sample_genesis() -> Genesis {
        let (c, f, e) = sample_configs();
        let chain = ChainId32::from_bytes([0x11; 32]);
        let alloc1 = Allocation {
            address: NativeAddress::from_bytes([0xaa; 20]),
            amount: Amount::from_sango(60_000_000).unwrap(),
            lock_schedule: LockSchedule::Unlocked,
        };
        let alloc2 = Allocation {
            address: NativeAddress::from_bytes([0xbb; 20]),
            amount: Amount::from_sango(40_000_000).unwrap(),
            lock_schedule: LockSchedule::Cliff {
                unlock_at: 1_800_000_000,
            },
        };
        Genesis {
            version: 1,
            chain_id: chain,
            timestamp: 1_700_000_000,
            initial_supply: Amount::from_sango(100_000_000).unwrap(),
            consensus_config: c,
            fee_config: f,
            evm_config: e,
            allocations: vec![alloc1, alloc2],
            validators: vec![GenesisValidator {
                address: NativeAddress::from_bytes([0xcc; 20]),
                public_key: PublicKey::from_bytes([0xdd; 32]),
                self_stake: Amount::from_sango(100_000).unwrap(),
                commission_bps: 700,
            }],
        }
    }

    #[test]
    fn evm_version_tag_roundtrip() {
        assert_eq!(
            EvmVersion::from_tag(EvmVersion::Prague.tag()).unwrap(),
            EvmVersion::Prague
        );
        assert!(EvmVersion::from_tag(0x00).is_err());
    }

    #[test]
    fn lock_schedule_roundtrip() {
        for s in [
            LockSchedule::Unlocked,
            LockSchedule::Cliff {
                unlock_at: 1_700_000_000,
            },
            LockSchedule::Linear {
                start: 0,
                end: 1_000_000,
            },
        ] {
            let bytes = s.encode_to_vec();
            assert_eq!(LockSchedule::decode_exact(&bytes).unwrap(), s);
        }
    }

    #[test]
    fn genesis_roundtrip() {
        let g = sample_genesis();
        let bytes = g.encode_to_vec();
        let decoded = Genesis::decode_exact(&bytes).unwrap();
        assert_eq!(decoded, g);
    }

    #[test]
    fn genesis_validate_ok() {
        let g = sample_genesis();
        assert!(g.validate().is_ok());
    }

    #[test]
    fn genesis_validate_sum_mismatch() {
        let mut g = sample_genesis();
        g.initial_supply = Amount::from_sango(999_999_999).unwrap();
        let err = g.validate().unwrap_err();
        assert!(matches!(err, TypeError::AllocationSumMismatch { .. }));
    }

    #[test]
    fn genesis_hash_deterministic() {
        let g = sample_genesis();
        assert_eq!(g.hash(), g.hash());
    }

    #[test]
    fn genesis_hash_changes_with_field() {
        let g = sample_genesis();
        let a = g.hash();
        let mut g2 = g.clone();
        g2.timestamp += 1;
        assert_ne!(a, g2.hash());
    }
}
