//! Résultat financier persistant d'une transaction.
//!
//! Complémentaire du [`crate::Receipt`] : le receipt décrit l'exécution
//! (gas, logs, statut), le `TxOutcome` décrit les **effets métier**
//! (récompenses réclamées, montant débloqué, date de maturité).
//!
//! ## Pourquoi
//!
//! Le wallet ne doit **jamais** reconstruire le résultat financier d'une
//! tx à partir de l'état post-hoc. Pour `ClaimRewards`, le montant est
//! calculé par le protocole au moment de l'exécution ; il est ensuite
//! persisté ici, et lu tel quel par le RPC.
//!
//! ## Encodage
//!
//! `Encode`/`Decode` via `sango-codec` (format canonique).

use sango_codec::{CodecError, Decode, Decoder, Encode, Encoder};
use sango_primitives::Amount;

/// Statut d'une transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TxOutcomeStatus {
    /// Échec (revert, halt EVM, etc.).
    Failed,
    /// Succès.
    Success,
}

impl TxOutcomeStatus {
    /// Tag canonique.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            TxOutcomeStatus::Failed => 0x00,
            TxOutcomeStatus::Success => 0x01,
        }
    }

    /// Parse un tag canonique.
    pub fn from_tag(tag: u8) -> Result<Self, CodecError> {
        match tag {
            0x00 => Ok(TxOutcomeStatus::Failed),
            0x01 => Ok(TxOutcomeStatus::Success),
            other => Err(CodecError::InvalidTag { tag: other }),
        }
    }
}

impl Encode for TxOutcomeStatus {
    fn encode(&self, enc: &mut Encoder) {
        enc.write_u8(self.tag());
    }
}

impl Decode for TxOutcomeStatus {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Self::from_tag(dec.read_u8()?)
    }
}

/// Résultat financier d'une transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxOutcome {
    /// Succès ou échec.
    pub status: TxOutcomeStatus,
    /// Gas consommé.
    pub gas_used: u64,
    /// Récompenses réclamées (`TxKind::ClaimRewards` uniquement).
    pub claimed_rewards: Option<Amount>,
    /// Montant débloqué (`TxKind::Unbond` / `TxKind::Undelegate`).
    pub unbond_amount: Option<Amount>,
    /// Timestamp Unix de maturité de l'unbond.
    pub unbond_mature_at: Option<u64>,
}

impl TxOutcome {
    /// Construit un outcome « succès simple » (aucun effet métier).
    #[must_use]
    pub const fn success(gas_used: u64) -> Self {
        Self {
            status: TxOutcomeStatus::Success,
            gas_used,
            claimed_rewards: None,
            unbond_amount: None,
            unbond_mature_at: None,
        }
    }

    /// Vrai si l'outcome ne porte aucune information métier.
    #[must_use]
    pub const fn is_plain(&self) -> bool {
        self.claimed_rewards.is_none()
            && self.unbond_amount.is_none()
            && self.unbond_mature_at.is_none()
    }
}

impl Encode for TxOutcome {
    fn encode(&self, enc: &mut Encoder) {
        self.status.encode(enc);
        self.gas_used.encode(enc);
        self.claimed_rewards.encode(enc);
        self.unbond_amount.encode(enc);
        self.unbond_mature_at.encode(enc);
    }
}

impl Decode for TxOutcome {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            status: TxOutcomeStatus::decode(dec)?,
            gas_used: u64::decode(dec)?,
            claimed_rewards: Option::<Amount>::decode(dec)?,
            unbond_amount: Option::<Amount>::decode(dec)?,
            unbond_mature_at: Option::<u64>::decode(dec)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_tag_roundtrip() {
        for s in [TxOutcomeStatus::Failed, TxOutcomeStatus::Success] {
            assert_eq!(TxOutcomeStatus::from_tag(s.tag()).unwrap(), s);
        }
        assert!(TxOutcomeStatus::from_tag(0x02).is_err());
    }

    #[test]
    fn outcome_roundtrip_plain() {
        let o = TxOutcome::success(21_000);
        let bytes = o.encode_to_vec();
        assert_eq!(TxOutcome::decode_exact(&bytes).unwrap(), o);
        assert!(o.is_plain());
    }

    #[test]
    fn outcome_roundtrip_claim() {
        let o = TxOutcome {
            status: TxOutcomeStatus::Success,
            gas_used: 40_000,
            claimed_rewards: Some(Amount::from_base_units(12_345_678)),
            unbond_amount: None,
            unbond_mature_at: None,
        };
        let bytes = o.encode_to_vec();
        assert_eq!(TxOutcome::decode_exact(&bytes).unwrap(), o);
    }

    #[test]
    fn outcome_roundtrip_unbond() {
        let o = TxOutcome {
            status: TxOutcomeStatus::Success,
            gas_used: 50_000,
            claimed_rewards: None,
            unbond_amount: Some(Amount::from_base_units(1_000_000_000)),
            unbond_mature_at: Some(1_800_000_000),
        };
        let bytes = o.encode_to_vec();
        assert_eq!(TxOutcome::decode_exact(&bytes).unwrap(), o);
    }
}
