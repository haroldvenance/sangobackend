//! Messages de consensus Sango V1.
//!
//! Contient : `Proposal`, `Prevote`, `Precommit`, `PrevoteCertificate`,
//! `CommitCertificate`.

use sango_codec::{CodecError, Decode, Decoder, Encode, Encoder};
use sango_crypto::{domain, sign_native, verify_native, CryptoError, NativeKeypair};
use sango_primitives::{
    ChainId32, Epoch, Hash32, Height, NativeAddress, PublicKey, Round, Signature,
};

use crate::block::Block;

// --- Proposal ---------------------------------------------------------------

/// Proposal consensus (Freeze, section 36).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proposal {
    /// Version du format.
    pub version: u32,
    /// Chain ID natif.
    pub chain_id: ChainId32,
    /// Index d'epoch.
    pub epoch: Epoch,
    /// Hauteur.
    pub height: Height,
    /// Round.
    pub round: Round,
    /// Bloc proposé.
    pub block: Block,
    /// Hash du bloc proposé.
    pub block_hash: Hash32,
    /// Dernier round avec PoLC connu (`None` = NIL).
    pub valid_round: Option<Round>,
    /// Certificat PoLC associé, si `valid_round` est `Some`.
    pub valid_round_certificate: Option<PrevoteCertificate>,
    /// Adresse du proposeur.
    pub proposer_address: NativeAddress,
    /// Signature du proposeur.
    pub proposer_signature: Signature,
}

impl Proposal {
    /// Encode les champs **hors** signature.
    #[must_use]
    pub fn encode_unsigned_to_vec(&self) -> Vec<u8> {
        let mut enc = Encoder::new();
        self.version.encode(&mut enc);
        self.chain_id.encode(&mut enc);
        self.epoch.encode(&mut enc);
        self.height.encode(&mut enc);
        self.round.encode(&mut enc);
        self.block_hash.encode(&mut enc);
        self.valid_round.encode(&mut enc);
        // Note : le certificat complet n'est pas inclus dans la signature,
        // seul `valid_round` (round) l'est. Voir Freeze, section 36.
        self.proposer_address.encode(&mut enc);
        enc.into_bytes()
    }

    /// Signature sur `DOMAIN_PROPOSAL_V1 || champs hors signature`.
    #[must_use]
    pub fn sign(&self, keypair: &NativeKeypair) -> Self {
        let sig = sign_native(keypair, domain::PROPOSAL_V1, &self.encode_unsigned_to_vec());
        let mut out = self.clone();
        out.proposer_signature = sig;
        out
    }

    /// Vérifie la signature du proposeur.
    pub fn verify(&self, public_key: &PublicKey) -> Result<(), CryptoError> {
        verify_native(
            public_key,
            domain::PROPOSAL_V1,
            &self.encode_unsigned_to_vec(),
            &self.proposer_signature,
        )
    }
}

impl Encode for Proposal {
    fn encode(&self, enc: &mut Encoder) {
        self.version.encode(enc);
        self.chain_id.encode(enc);
        self.epoch.encode(enc);
        self.height.encode(enc);
        self.round.encode(enc);
        self.block.encode(enc);
        self.block_hash.encode(enc);
        self.valid_round.encode(enc);
        self.valid_round_certificate.encode(enc);
        self.proposer_address.encode(enc);
        self.proposer_signature.encode(enc);
    }
}

impl Decode for Proposal {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            version: u32::decode(dec)?,
            chain_id: ChainId32::decode(dec)?,
            epoch: Epoch::decode(dec)?,
            height: Height::decode(dec)?,
            round: Round::decode(dec)?,
            block: Block::decode(dec)?,
            block_hash: Hash32::decode(dec)?,
            valid_round: Option::<Round>::decode(dec)?,
            valid_round_certificate: Option::<PrevoteCertificate>::decode(dec)?,
            proposer_address: NativeAddress::decode(dec)?,
            proposer_signature: Signature::decode(dec)?,
        })
    }
}

// --- Prevote ---------------------------------------------------------------

/// Prevote consensus (Freeze, section 37).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Prevote {
    /// Chain ID natif.
    pub chain_id: ChainId32,
    /// Index d'epoch.
    pub epoch: Epoch,
    /// Hauteur.
    pub height: Height,
    /// Round.
    pub round: Round,
    /// Hash du bloc voté (`None` = NIL).
    pub block_hash: Option<Hash32>,
    /// Adresse du validateur.
    pub validator_address: NativeAddress,
    /// Signature Ed25519.
    pub validator_signature: Signature,
}

impl Prevote {
    /// Encode les champs **hors** signature.
    #[must_use]
    pub fn encode_unsigned_to_vec(&self) -> Vec<u8> {
        let mut enc = Encoder::new();
        self.chain_id.encode(&mut enc);
        self.epoch.encode(&mut enc);
        self.height.encode(&mut enc);
        self.round.encode(&mut enc);
        self.block_hash.encode(&mut enc);
        self.validator_address.encode(&mut enc);
        enc.into_bytes()
    }

    /// Signe la prevote.
    #[must_use]
    pub fn sign(&self, keypair: &NativeKeypair) -> Self {
        let sig = sign_native(keypair, domain::PREVOTE_V1, &self.encode_unsigned_to_vec());
        let mut out = *self;
        out.validator_signature = sig;
        out
    }

    /// Vérifie la signature.
    pub fn verify(&self, public_key: &PublicKey) -> Result<(), CryptoError> {
        verify_native(
            public_key,
            domain::PREVOTE_V1,
            &self.encode_unsigned_to_vec(),
            &self.validator_signature,
        )
    }
}

impl Encode for Prevote {
    fn encode(&self, enc: &mut Encoder) {
        self.chain_id.encode(enc);
        self.epoch.encode(enc);
        self.height.encode(enc);
        self.round.encode(enc);
        self.block_hash.encode(enc);
        self.validator_address.encode(enc);
        self.validator_signature.encode(enc);
    }
}

impl Decode for Prevote {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            chain_id: ChainId32::decode(dec)?,
            epoch: Epoch::decode(dec)?,
            height: Height::decode(dec)?,
            round: Round::decode(dec)?,
            block_hash: Option::<Hash32>::decode(dec)?,
            validator_address: NativeAddress::decode(dec)?,
            validator_signature: Signature::decode(dec)?,
        })
    }
}

// --- Precommit --------------------------------------------------------------

/// Precommit consensus (Freeze, section 38).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Precommit {
    /// Chain ID natif.
    pub chain_id: ChainId32,
    /// Index d'epoch.
    pub epoch: Epoch,
    /// Hauteur.
    pub height: Height,
    /// Round.
    pub round: Round,
    /// Hash du bloc pré-committé (`None` = NIL).
    pub block_hash: Option<Hash32>,
    /// Adresse du validateur.
    pub validator_address: NativeAddress,
    /// Signature Ed25519.
    pub validator_signature: Signature,
}

impl Precommit {
    /// Encode les champs **hors** signature.
    #[must_use]
    pub fn encode_unsigned_to_vec(&self) -> Vec<u8> {
        let mut enc = Encoder::new();
        self.chain_id.encode(&mut enc);
        self.epoch.encode(&mut enc);
        self.height.encode(&mut enc);
        self.round.encode(&mut enc);
        self.block_hash.encode(&mut enc);
        self.validator_address.encode(&mut enc);
        enc.into_bytes()
    }

    /// Signe le precommit.
    #[must_use]
    pub fn sign(&self, keypair: &NativeKeypair) -> Self {
        let sig = sign_native(
            keypair,
            domain::PRECOMMIT_V1,
            &self.encode_unsigned_to_vec(),
        );
        let mut out = *self;
        out.validator_signature = sig;
        out
    }

    /// Vérifie la signature.
    pub fn verify(&self, public_key: &PublicKey) -> Result<(), CryptoError> {
        verify_native(
            public_key,
            domain::PRECOMMIT_V1,
            &self.encode_unsigned_to_vec(),
            &self.validator_signature,
        )
    }
}

impl Encode for Precommit {
    fn encode(&self, enc: &mut Encoder) {
        self.chain_id.encode(enc);
        self.epoch.encode(enc);
        self.height.encode(enc);
        self.round.encode(enc);
        self.block_hash.encode(enc);
        self.validator_address.encode(enc);
        self.validator_signature.encode(enc);
    }
}

impl Decode for Precommit {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            chain_id: ChainId32::decode(dec)?,
            epoch: Epoch::decode(dec)?,
            height: Height::decode(dec)?,
            round: Round::decode(dec)?,
            block_hash: Option::<Hash32>::decode(dec)?,
            validator_address: NativeAddress::decode(dec)?,
            validator_signature: Signature::decode(dec)?,
        })
    }
}

// --- Certificats ------------------------------------------------------------

/// Entrée d'une prevote dans un certificat.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrevoteEntry {
    /// Adresse du validateur signataire.
    pub validator_address: NativeAddress,
    /// Signature sur la prevote.
    pub signature: Signature,
}

impl Encode for PrevoteEntry {
    fn encode(&self, enc: &mut Encoder) {
        self.validator_address.encode(enc);
        self.signature.encode(enc);
    }
}

impl Decode for PrevoteEntry {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            validator_address: NativeAddress::decode(dec)?,
            signature: Signature::decode(dec)?,
        })
    }
}

/// Certificat de prevote (PoLC), Freeze section 39.
///
/// Les entrées sont triées par adresse de validateur croissante. La
/// puissance de vote n'est **jamais** déduite du certificat : elle est
/// recalculée localement à partir du validator set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrevoteCertificate {
    /// Version du format.
    pub version: u32,
    /// Chain ID natif.
    pub chain_id: ChainId32,
    /// Epoch.
    pub epoch: Epoch,
    /// Hauteur.
    pub height: Height,
    /// Round.
    pub round: Round,
    /// Hash de bloc (`None` = NIL).
    pub block_hash: Option<Hash32>,
    /// Entrées triées par `validator_address` croissante.
    pub prevotes: Vec<PrevoteEntry>,
}

impl Encode for PrevoteCertificate {
    fn encode(&self, enc: &mut Encoder) {
        self.version.encode(enc);
        self.chain_id.encode(enc);
        self.epoch.encode(enc);
        self.height.encode(enc);
        self.round.encode(enc);
        self.block_hash.encode(enc);
        self.prevotes.encode(enc);
    }
}

impl Decode for PrevoteCertificate {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            version: u32::decode(dec)?,
            chain_id: ChainId32::decode(dec)?,
            epoch: Epoch::decode(dec)?,
            height: Height::decode(dec)?,
            round: Round::decode(dec)?,
            block_hash: Option::<Hash32>::decode(dec)?,
            prevotes: Vec::<PrevoteEntry>::decode(dec)?,
        })
    }
}

/// Entrée d'un precommit dans un certificat.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrecommitEntry {
    /// Adresse du validateur signataire.
    pub validator_address: NativeAddress,
    /// Signature sur le precommit.
    pub signature: Signature,
}

impl Encode for PrecommitEntry {
    fn encode(&self, enc: &mut Encoder) {
        self.validator_address.encode(enc);
        self.signature.encode(enc);
    }
}

impl Decode for PrecommitEntry {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            validator_address: NativeAddress::decode(dec)?,
            signature: Signature::decode(dec)?,
        })
    }
}

/// Certificat de commit, Freeze section 43.
///
/// Les entrées sont triées par adresse de validateur croissante.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitCertificate {
    /// Version du format.
    pub version: u32,
    /// Chain ID natif.
    pub chain_id: ChainId32,
    /// Epoch.
    pub epoch: Epoch,
    /// Hauteur.
    pub height: Height,
    /// Round.
    pub round: Round,
    /// Hash du bloc committé.
    pub block_hash: Hash32,
    /// Entrées triées par `validator_address` croissante.
    pub precommits: Vec<PrecommitEntry>,
}

impl Encode for CommitCertificate {
    fn encode(&self, enc: &mut Encoder) {
        self.version.encode(enc);
        self.chain_id.encode(enc);
        self.epoch.encode(enc);
        self.height.encode(enc);
        self.round.encode(enc);
        self.block_hash.encode(enc);
        self.precommits.encode(enc);
    }
}

impl Decode for CommitCertificate {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            version: u32::decode(dec)?,
            chain_id: ChainId32::decode(dec)?,
            epoch: Epoch::decode(dec)?,
            height: Height::decode(dec)?,
            round: Round::decode(dec)?,
            block_hash: Hash32::decode(dec)?,
            precommits: Vec::<PrecommitEntry>::decode(dec)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::Block;
    use crate::header::BlockHeader;
    use crate::transaction::TxKind;
    use sango_primitives::Amount;

    fn chain() -> ChainId32 {
        ChainId32::from_bytes([0x11; 32])
    }

    fn addr(b: u8) -> NativeAddress {
        NativeAddress::from_bytes([b; 20])
    }

    fn sample_header() -> BlockHeader {
        BlockHeader {
            version: 1,
            chain_id: chain(),
            epoch: Epoch::new(0),
            height: Height::new(1),
            round: Round::new(0),
            previous_block_hash: Hash32::from_bytes([0x22; 32]),
            timestamp: 1_700_000_000,
            proposer_address: addr(0x33),
            transaction_root: Hash32::from_bytes([0x44; 32]),
            state_root: Hash32::from_bytes([0x55; 32]),
            receipt_root: Hash32::from_bytes([0x66; 32]),
            gas_used: 0,
            gas_limit: 30_000_000,
            base_fee: 1,
        }
    }

    fn sample_block() -> Block {
        Block {
            header: sample_header(),
            transactions: Vec::new(),
        }
    }

    fn sample_proposal() -> Proposal {
        let block = sample_block();
        let block_hash = block.hash();
        Proposal {
            version: 1,
            chain_id: chain(),
            epoch: Epoch::new(0),
            height: Height::new(1),
            round: Round::new(0),
            block,
            block_hash,
            valid_round: None,
            valid_round_certificate: None,
            proposer_address: addr(0x33),
            proposer_signature: Signature::ZERO,
        }
    }

    #[test]
    fn prevote_with_block_roundtrip() {
        let v = Prevote {
            chain_id: chain(),
            epoch: Epoch::new(0),
            height: Height::new(1),
            round: Round::new(0),
            block_hash: Some(Hash32::from_bytes([0xaa; 32])),
            validator_address: addr(0xbb),
            validator_signature: Signature::ZERO,
        };
        let bytes = v.encode_to_vec();
        assert_eq!(Prevote::decode_exact(&bytes).unwrap(), v);
    }

    #[test]
    fn prevote_nil_roundtrip() {
        let v = Prevote {
            chain_id: chain(),
            epoch: Epoch::new(0),
            height: Height::new(1),
            round: Round::new(0),
            block_hash: None,
            validator_address: addr(0xbb),
            validator_signature: Signature::ZERO,
        };
        let bytes = v.encode_to_vec();
        assert_eq!(Prevote::decode_exact(&bytes).unwrap(), v);
    }

    #[test]
    fn prevote_sign_verify() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let pk = kp.public_key();
        let v = Prevote {
            chain_id: chain(),
            epoch: Epoch::new(0),
            height: Height::new(1),
            round: Round::new(0),
            block_hash: Some(Hash32::from_bytes([0xaa; 32])),
            validator_address: addr(0xbb),
            validator_signature: Signature::ZERO,
        }
        .sign(&kp);
        assert!(v.verify(&pk).is_ok());
    }

    #[test]
    fn prevote_tamper_fails() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let pk = kp.public_key();
        let v = Prevote {
            chain_id: chain(),
            epoch: Epoch::new(0),
            height: Height::new(1),
            round: Round::new(0),
            block_hash: Some(Hash32::from_bytes([0xaa; 32])),
            validator_address: addr(0xbb),
            validator_signature: Signature::ZERO,
        }
        .sign(&kp);
        let mut t = v;
        t.round = Round::new(1);
        assert!(t.verify(&pk).is_err());
    }

    #[test]
    fn precommit_roundtrip_and_sign() {
        let kp = NativeKeypair::from_seed([0x43; 32]);
        let pk = kp.public_key();
        let c = Precommit {
            chain_id: chain(),
            epoch: Epoch::new(0),
            height: Height::new(1),
            round: Round::new(0),
            block_hash: Some(Hash32::from_bytes([0xaa; 32])),
            validator_address: addr(0xbb),
            validator_signature: Signature::ZERO,
        }
        .sign(&kp);
        assert!(c.verify(&pk).is_ok());
        let bytes = c.encode_to_vec();
        assert_eq!(Precommit::decode_exact(&bytes).unwrap(), c);
    }

    #[test]
    fn proposal_roundtrip() {
        let p = sample_proposal();
        let bytes = p.encode_to_vec();
        assert_eq!(Proposal::decode_exact(&bytes).unwrap(), p);
    }

    #[test]
    fn proposal_sign_verify() {
        let kp = NativeKeypair::from_seed([0x44; 32]);
        let pk = kp.public_key();
        let p = sample_proposal().sign(&kp);
        assert!(p.verify(&pk).is_ok());
    }

    #[test]
    fn proposal_with_valid_round_roundtrip() {
        let kp = NativeKeypair::from_seed([0x44; 32]);
        let entry = PrevoteEntry {
            validator_address: addr(0xcc),
            signature: Signature::ZERO,
        };
        let cert = PrevoteCertificate {
            version: 1,
            chain_id: chain(),
            epoch: Epoch::new(0),
            height: Height::new(1),
            round: Round::new(0),
            block_hash: Some(Hash32::from_bytes([0xaa; 32])),
            prevotes: vec![entry],
        };
        let mut p = sample_proposal();
        p.valid_round = Some(Round::new(0));
        p.valid_round_certificate = Some(cert);
        let p = p.sign(&kp);

        let bytes = p.encode_to_vec();
        let decoded = Proposal::decode_exact(&bytes).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn prevote_certificate_roundtrip() {
        let cert = PrevoteCertificate {
            version: 1,
            chain_id: chain(),
            epoch: Epoch::new(0),
            height: Height::new(1),
            round: Round::new(0),
            block_hash: Some(Hash32::from_bytes([0xaa; 32])),
            prevotes: vec![
                PrevoteEntry {
                    validator_address: addr(0xcc),
                    signature: Signature::ZERO,
                },
                PrevoteEntry {
                    validator_address: addr(0xdd),
                    signature: Signature::ZERO,
                },
            ],
        };
        let bytes = cert.encode_to_vec();
        assert_eq!(PrevoteCertificate::decode_exact(&bytes).unwrap(), cert);
    }

    #[test]
    fn commit_certificate_roundtrip() {
        let cert = CommitCertificate {
            version: 1,
            chain_id: chain(),
            epoch: Epoch::new(0),
            height: Height::new(1),
            round: Round::new(0),
            block_hash: Hash32::from_bytes([0xaa; 32]),
            precommits: vec![PrecommitEntry {
                validator_address: addr(0xcc),
                signature: Signature::ZERO,
            }],
        };
        let bytes = cert.encode_to_vec();
        assert_eq!(CommitCertificate::decode_exact(&bytes).unwrap(), cert);
    }

    // Marqueur pour éviter unused warnings dans ce module de test.
    #[allow(dead_code)]
    fn _unused() {
        let _ = Amount::ZERO;
        let _ = TxKind::Transfer;
    }
}
