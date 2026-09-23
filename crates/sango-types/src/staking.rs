//! Types de staking Sango V1.

use sango_codec::{CodecError, Decode, Decoder, Encode, Encoder};
use sango_primitives::{Amount, NativeAddress, PublicKey};

/// Informations d'un validateur enregistré.
///
/// Stocké dans le namespace `Validator` sous la clé `validator_address`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatorInfo {
    /// Adresse native du validateur.
    pub address: NativeAddress,
    /// Clé publique Ed25519 pour les signatures consensus.
    pub public_key: PublicKey,
    /// Self-stake actuellement bonded (base units).
    pub self_stake: Amount,
    /// Délégations actives totales (base units).
    pub total_delegated: Amount,
    /// Commission courante en basis points (`700` = 7 %). Max `1000`.
    pub commission_bps: u32,
    /// Commission en attente, si une modification a été demandée.
    pub pending_commission_bps: Option<u32>,
    /// Timestamp Unix à partir duquel la commission en attente s'applique.
    pub pending_commission_at: Option<u64>,
    /// Vrai si le validateur est actuellement en jail.
    pub jailed: bool,
    /// Timestamp Unix de sortie automatique du jail (si connu).
    pub jailed_until: Option<u64>,
    /// Hauteur du début de la fenêtre de downtime courante.
    pub downtime_window_start: u64,
    /// Nombre de blocs manqués dans la fenêtre courante.
    pub downtime_missed: u32,
}

impl ValidatorInfo {
    /// Vrai si le validateur est actif (non jailed).
    #[must_use]
    pub const fn is_active(&self) -> bool {
        !self.jailed
    }

    /// Puissance de vote : `self_stake + total_delegated`.
    #[must_use]
    pub fn voting_power(&self) -> Amount {
        self.self_stake
            .checked_add(self.total_delegated)
            .unwrap_or(self.self_stake)
    }
}

impl Encode for ValidatorInfo {
    fn encode(&self, enc: &mut Encoder) {
        self.address.encode(enc);
        self.public_key.encode(enc);
        self.self_stake.encode(enc);
        self.total_delegated.encode(enc);
        self.commission_bps.encode(enc);
        self.pending_commission_bps.encode(enc);
        self.pending_commission_at.encode(enc);
        self.jailed.encode(enc);
        self.jailed_until.encode(enc);
        self.downtime_window_start.encode(enc);
        self.downtime_missed.encode(enc);
    }
}

impl Decode for ValidatorInfo {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            address: NativeAddress::decode(dec)?,
            public_key: PublicKey::decode(dec)?,
            self_stake: Amount::decode(dec)?,
            total_delegated: Amount::decode(dec)?,
            commission_bps: u32::decode(dec)?,
            pending_commission_bps: Option::<u32>::decode(dec)?,
            pending_commission_at: Option::<u64>::decode(dec)?,
            jailed: bool::decode(dec)?,
            jailed_until: Option::<u64>::decode(dec)?,
            downtime_window_start: u64::decode(dec)?,
            downtime_missed: u32::decode(dec)?,
        })
    }
}

/// Délégation d'un compte vers un validateur.
///
/// Stocké dans le namespace `Delegation` sous la clé
/// `delegator_address || validator_address`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Delegation {
    /// Adresse du délégateur.
    pub delegator: NativeAddress,
    /// Adresse du validateur.
    pub validator: NativeAddress,
    /// Montant bonded (base units).
    pub bonded: Amount,
    /// Montant en cours d'unbonding (base units).
    pub unbonding: Amount,
    /// Timestamp Unix de libération du montant en unbonding.
    pub unbonding_until: Option<u64>,
    /// Récompenses accumulées non réclamées (base units).
    pub pending_rewards: Amount,
}

impl Delegation {
    /// Crée une délégation vide.
    #[must_use]
    pub const fn empty(delegator: NativeAddress, validator: NativeAddress) -> Self {
        Self {
            delegator,
            validator,
            bonded: Amount::ZERO,
            unbonding: Amount::ZERO,
            unbonding_until: None,
            pending_rewards: Amount::ZERO,
        }
    }

    /// Vrai si la délégation est vide.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bonded.is_zero() && self.unbonding.is_zero() && self.pending_rewards.is_zero()
    }
}

impl Encode for Delegation {
    fn encode(&self, enc: &mut Encoder) {
        self.delegator.encode(enc);
        self.validator.encode(enc);
        self.bonded.encode(enc);
        self.unbonding.encode(enc);
        self.unbonding_until.encode(enc);
        self.pending_rewards.encode(enc);
    }
}

impl Decode for Delegation {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            delegator: NativeAddress::decode(dec)?,
            validator: NativeAddress::decode(dec)?,
            bonded: Amount::decode(dec)?,
            unbonding: Amount::decode(dec)?,
            unbonding_until: Option::<u64>::decode(dec)?,
            pending_rewards: Amount::decode(dec)?,
        })
    }
}

/// Paramètres normatifs du staking V1 (Freeze sections 13, 46-50).
pub mod params {
    use sango_primitives::{Amount, BASE_UNITS_PER_SANGO};

    /// Self-stake minimum pour être validateur.
    #[must_use]
    pub fn min_self_stake() -> Amount {
        Amount::from_base_units(100_000 * BASE_UNITS_PER_SANGO)
    }

    /// Commission maximale en basis points (10 %).
    pub const MAX_COMMISSION_BPS: u32 = 1_000;

    /// Délai de modification de commission (7 jours).
    pub const COMMISSION_UPDATE_DELAY_SECS: u64 = 7 * 24 * 3600;

    /// Durée d'unbonding (14 jours).
    pub const UNBONDING_PERIOD_SECS: u64 = 14 * 24 * 3600;

    /// Slash double-sign en basis points (5 %).
    pub const DOUBLE_SIGN_SLASH_BPS: u32 = 500;

    /// Seuil de downtime en basis points (80 %).
    pub const DOWNTIME_THRESHOLD_BPS: u32 = 8_000;

    /// Fenêtre de downtime (100 blocs).
    pub const DOWNTIME_WINDOW: u64 = 100;

    /// Nombre maximum de validateurs actifs.
    pub const MAX_ACTIVE_VALIDATORS: u32 = 100;

    /// Durée du jail automatique pour downtime (5000 blocs ≈ 7 h).
    pub const DOWNTIME_JAIL_BLOCKS: u64 = 5_000;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> NativeAddress {
        NativeAddress::from_bytes([b; 20])
    }

    #[test]
    fn validator_info_roundtrip() {
        let v = ValidatorInfo {
            address: addr(0xaa),
            public_key: PublicKey::from_bytes([0x01; 32]),
            self_stake: Amount::from_sango(100_000).unwrap(),
            total_delegated: Amount::from_sango(50_000).unwrap(),
            commission_bps: 700,
            pending_commission_bps: Some(800),
            pending_commission_at: Some(1_800_000_000),
            jailed: false,
            jailed_until: None,
            downtime_window_start: 0,
            downtime_missed: 0,
        };
        let bytes = v.encode_to_vec();
        assert_eq!(ValidatorInfo::decode_exact(&bytes).unwrap(), v);
    }

    #[test]
    fn validator_info_jailed_roundtrip() {
        let v = ValidatorInfo {
            address: addr(0xaa),
            public_key: PublicKey::from_bytes([0x01; 32]),
            self_stake: Amount::from_sango(100_000).unwrap(),
            total_delegated: Amount::ZERO,
            commission_bps: 700,
            pending_commission_bps: None,
            pending_commission_at: None,
            jailed: true,
            jailed_until: Some(1_800_000_000),
            downtime_window_start: 0,
            downtime_missed: 0,
        };
        let bytes = v.encode_to_vec();
        assert_eq!(ValidatorInfo::decode_exact(&bytes).unwrap(), v);
    }

    #[test]
    fn voting_power_sums_stakes() {
        let v = ValidatorInfo {
            address: addr(0xaa),
            public_key: PublicKey::from_bytes([0x01; 32]),
            self_stake: Amount::from_sango(100_000).unwrap(),
            total_delegated: Amount::from_sango(50_000).unwrap(),
            commission_bps: 700,
            pending_commission_bps: None,
            pending_commission_at: None,
            jailed: false,
            jailed_until: None,
            downtime_window_start: 0,
            downtime_missed: 0,
        };
        assert_eq!(v.voting_power(), Amount::from_sango(150_000).unwrap());
    }

    #[test]
    fn delegation_roundtrip() {
        let d = Delegation {
            delegator: addr(0xbb),
            validator: addr(0xaa),
            bonded: Amount::from_sango(1_000).unwrap(),
            unbonding: Amount::from_sango(500).unwrap(),
            unbonding_until: Some(1_800_000_000),
            pending_rewards: Amount::from_base_units(12345),
        };
        let bytes = d.encode_to_vec();
        assert_eq!(Delegation::decode_exact(&bytes).unwrap(), d);
    }

    #[test]
    fn delegation_empty_is_empty() {
        let d = Delegation::empty(addr(0xbb), addr(0xaa));
        assert!(d.is_empty());
    }

    #[test]
    fn params_match_freeze() {
        use super::params::*;
        assert_eq!(min_self_stake().base_units(), 100_000 * 10_000_000);
        assert_eq!(MAX_COMMISSION_BPS, 1_000);
        assert_eq!(COMMISSION_UPDATE_DELAY_SECS, 7 * 24 * 3600);
        assert_eq!(UNBONDING_PERIOD_SECS, 14 * 24 * 3600);
        assert_eq!(DOUBLE_SIGN_SLASH_BPS, 500);
        assert_eq!(DOWNTIME_THRESHOLD_BPS, 8_000);
        assert_eq!(DOWNTIME_WINDOW, 100);
        assert_eq!(MAX_ACTIVE_VALIDATORS, 100);
        assert_eq!(DOWNTIME_JAIL_BLOCKS, 5_000);
    }
}
