//! Enregistrement d'une evidence déjà appliquée.
//!
//! Persisté dans le namespace `Evidence` sous la clé `evidence_id`. Sa
//! présence empêche un second slash pour la même evidence (Freeze section 46).

use sango_codec::{CodecError, Decode, Decoder, Encode, Encoder};
use sango_primitives::{Amount, Hash32, NativeAddress};

/// Enregistrement d'une evidence appliquée.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct EvidenceRecord {
    /// Identifiant canonique : `Keccak256("SANGO/EVIDENCE/V1" || evidence)`.
    pub evidence_id: Hash32,
    /// Validateur fautif.
    pub validator_address: NativeAddress,
    /// Hauteur à laquelle l'evidence a été appliquée.
    pub applied_at_height: u64,
    /// Montant slashé (base units).
    pub slashed: Amount,
}

impl Encode for EvidenceRecord {
    fn encode(&self, enc: &mut Encoder) {
        self.evidence_id.encode(enc);
        self.validator_address.encode(enc);
        self.applied_at_height.encode(enc);
        self.slashed.encode(enc);
    }
}

impl Decode for EvidenceRecord {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            evidence_id: Hash32::decode(dec)?,
            validator_address: NativeAddress::decode(dec)?,
            applied_at_height: u64::decode(dec)?,
            slashed: Amount::decode(dec)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let r = EvidenceRecord {
            evidence_id: Hash32::from_bytes([0xab; 32]),
            validator_address: NativeAddress::from_bytes([0xcd; 20]),
            applied_at_height: 12345,
            slashed: Amount::from_base_units(999_999),
        };
        let bytes = r.encode_to_vec();
        assert_eq!(EvidenceRecord::decode_exact(&bytes).unwrap(), r);
    }

    #[test]
    fn encoding_size_is_fixed() {
        let r = EvidenceRecord {
            evidence_id: Hash32::ZERO,
            validator_address: NativeAddress::ZERO,
            applied_at_height: 0,
            slashed: Amount::ZERO,
        };
        // 32 + 20 + 8 + 16 = 76
        assert_eq!(r.encode_to_vec().len(), 76);
    }
}
