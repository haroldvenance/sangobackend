//! Evidence consensus Sango V1.
//!
//! Contient : `EvidenceType`, `ConsensusMessageType`, `ConsensusMessage`,
//! `Evidence`.

use sango_codec::{CodecError, Decode, Decoder, Encode, Encoder};
use sango_crypto::{domain, keccak256};
use sango_primitives::{ChainId32, Epoch, Hash32, Height, NativeAddress, Round, Signature};

/// Type d'evidence (Freeze, section 45).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum EvidenceType {
    /// Double prevote.
    DoublePrevote,
    /// Double precommit.
    DoublePrecommit,
}

impl EvidenceType {
    /// Tag canonique.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            EvidenceType::DoublePrevote => 0x01,
            EvidenceType::DoublePrecommit => 0x02,
        }
    }

    /// Parse un tag canonique.
    pub fn from_tag(tag: u8) -> Result<Self, CodecError> {
        match tag {
            0x01 => Ok(EvidenceType::DoublePrevote),
            0x02 => Ok(EvidenceType::DoublePrecommit),
            other => Err(CodecError::InvalidTag { tag: other }),
        }
    }
}

impl Encode for EvidenceType {
    fn encode(&self, enc: &mut Encoder) {
        enc.write_u8(self.tag());
    }
}

impl Decode for EvidenceType {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Self::from_tag(dec.read_u8()?)
    }
}

/// Type de message consensus contenu dans une evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ConsensusMessageType {
    /// Prevote.
    Prevote,
    /// Precommit.
    Precommit,
}

impl ConsensusMessageType {
    /// Tag canonique.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            ConsensusMessageType::Prevote => 0x01,
            ConsensusMessageType::Precommit => 0x02,
        }
    }

    /// Parse un tag canonique.
    pub fn from_tag(tag: u8) -> Result<Self, CodecError> {
        match tag {
            0x01 => Ok(ConsensusMessageType::Prevote),
            0x02 => Ok(ConsensusMessageType::Precommit),
            other => Err(CodecError::InvalidTag { tag: other }),
        }
    }
}

impl Encode for ConsensusMessageType {
    fn encode(&self, enc: &mut Encoder) {
        enc.write_u8(self.tag());
    }
}

impl Decode for ConsensusMessageType {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Self::from_tag(dec.read_u8()?)
    }
}

/// Message consensus inclus dans une evidence.
///
/// Le `canonical_payload` contient les bytes signés par le validateur
/// (sans le domain separator, qui est appliqué lors de la vérification).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsensusMessage {
    /// Type du message (`Prevote` ou `Precommit`).
    pub message_type: ConsensusMessageType,
    /// Payload canonique du message.
    pub canonical_payload: Vec<u8>,
    /// Signature Ed25519.
    pub signature: Signature,
}

impl Encode for ConsensusMessage {
    fn encode(&self, enc: &mut Encoder) {
        self.message_type.encode(enc);
        self.canonical_payload.encode(enc);
        self.signature.encode(enc);
    }
}

impl Decode for ConsensusMessage {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            message_type: ConsensusMessageType::decode(dec)?,
            canonical_payload: Vec::<u8>::decode(dec)?,
            signature: Signature::decode(dec)?,
        })
    }
}

/// Evidence consensus (Freeze, section 45).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Evidence {
    /// Version du format.
    pub version: u32,
    /// Type d'evidence.
    pub evidence_type: EvidenceType,
    /// Chain ID natif.
    pub chain_id: ChainId32,
    /// Epoch.
    pub epoch: Epoch,
    /// Hauteur.
    pub height: Height,
    /// Round.
    pub round: Round,
    /// Validateur fautif.
    pub validator_address: NativeAddress,
    /// Premier message.
    pub message_1: ConsensusMessage,
    /// Second message, contradictoire avec le premier.
    pub message_2: ConsensusMessage,
}

impl Evidence {
    /// Identifiant canonique :
    ///
    /// ```text
    /// evidence_id = Keccak256("SANGO/EVIDENCE/V1" || canonical(evidence))
    /// ```
    ///
    /// Deux evidences ayant le même `evidence_id` sont identiques ; le nœud
    /// doit conserver les IDs déjà traités pour empêcher un double slash.
    #[must_use]
    pub fn evidence_id(&self) -> Hash32 {
        let mut enc = Encoder::new();
        enc.write_raw(domain::EVIDENCE_V1);
        self.encode(&mut enc);
        keccak256(enc.as_slice())
    }
}

impl Encode for Evidence {
    fn encode(&self, enc: &mut Encoder) {
        self.version.encode(enc);
        self.evidence_type.encode(enc);
        self.chain_id.encode(enc);
        self.epoch.encode(enc);
        self.height.encode(enc);
        self.round.encode(enc);
        self.validator_address.encode(enc);
        self.message_1.encode(enc);
        self.message_2.encode(enc);
    }
}

impl Decode for Evidence {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            version: u32::decode(dec)?,
            evidence_type: EvidenceType::decode(dec)?,
            chain_id: ChainId32::decode(dec)?,
            epoch: Epoch::decode(dec)?,
            height: Height::decode(dec)?,
            round: Round::decode(dec)?,
            validator_address: NativeAddress::decode(dec)?,
            message_1: ConsensusMessage::decode(dec)?,
            message_2: ConsensusMessage::decode(dec)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain() -> ChainId32 {
        ChainId32::from_bytes([0x11; 32])
    }

    fn addr(b: u8) -> NativeAddress {
        NativeAddress::from_bytes([b; 20])
    }

    fn msg(kind: ConsensusMessageType, payload: &[u8]) -> ConsensusMessage {
        ConsensusMessage {
            message_type: kind,
            canonical_payload: payload.to_vec(),
            signature: Signature::ZERO,
        }
    }

    fn sample_evidence() -> Evidence {
        Evidence {
            version: 1,
            evidence_type: EvidenceType::DoublePrevote,
            chain_id: chain(),
            epoch: Epoch::new(0),
            height: Height::new(100),
            round: Round::new(0),
            validator_address: addr(0xaa),
            message_1: msg(ConsensusMessageType::Prevote, &[0x01, 0x02]),
            message_2: msg(ConsensusMessageType::Prevote, &[0x03, 0x04]),
        }
    }

    #[test]
    fn evidence_type_tag_roundtrip() {
        for t in [EvidenceType::DoublePrevote, EvidenceType::DoublePrecommit] {
            assert_eq!(EvidenceType::from_tag(t.tag()).unwrap(), t);
        }
        assert!(EvidenceType::from_tag(0x00).is_err());
    }

    #[test]
    fn consensus_message_type_tag_roundtrip() {
        for t in [
            ConsensusMessageType::Prevote,
            ConsensusMessageType::Precommit,
        ] {
            assert_eq!(ConsensusMessageType::from_tag(t.tag()).unwrap(), t);
        }
        assert!(ConsensusMessageType::from_tag(0x00).is_err());
    }

    #[test]
    fn evidence_roundtrip() {
        let e = sample_evidence();
        let bytes = e.encode_to_vec();
        assert_eq!(Evidence::decode_exact(&bytes).unwrap(), e);
    }

    #[test]
    fn evidence_id_is_deterministic() {
        let e = sample_evidence();
        assert_eq!(e.evidence_id(), e.evidence_id());
    }

    #[test]
    fn evidence_id_changes_with_field() {
        let e = sample_evidence();
        let a = e.evidence_id();
        let mut e2 = e;
        e2.height = Height::new(101);
        assert_ne!(a, e2.evidence_id());
    }

    #[test]
    fn evidence_id_changes_with_payload() {
        let e = sample_evidence();
        let a = e.evidence_id();
        let mut e2 = e;
        e2.message_1.canonical_payload = vec![0xff];
        assert_ne!(a, e2.evidence_id());
    }
}
