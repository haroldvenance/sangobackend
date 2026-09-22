//! En-tête de bloc et calcul du `block_hash`.

use sango_codec::{Decode, Decoder, Encode, Encoder};
use sango_crypto::{domain, keccak256};
use sango_primitives::{ChainId32, Epoch, Hash32, Height, NativeAddress, Round};

/// En-tête de bloc Sango V1 (Freeze, section 18).
///
/// Ordre canonique des champs (normatif) :
///
/// ```text
/// version || chain_id || epoch || height || round
/// || previous_block_hash || timestamp || proposer_address
/// || transaction_root || state_root || receipt_root
/// || gas_used || gas_limit
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct BlockHeader {
    /// Version du protocole. `1` pour V1.
    pub version: u32,
    /// Chain ID natif (32 bytes).
    pub chain_id: ChainId32,
    /// Index d'epoch.
    pub epoch: Epoch,
    /// Hauteur du bloc.
    pub height: Height,
    /// Round de consensus à cette hauteur.
    pub round: Round,
    /// Hash du bloc précédent.
    pub previous_block_hash: Hash32,
    /// Timestamp Unix en secondes.
    pub timestamp: u64,
    /// Adresse native du proposeur.
    pub proposer_address: NativeAddress,
    /// Racine MPT des transactions du bloc.
    pub transaction_root: Hash32,
    /// `Keccak256("SANGO/STATE/ROOT/V1" || native_root || evm_root)`.
    pub state_root: Hash32,
    /// Racine MPT des receipts du bloc.
    pub receipt_root: Hash32,
    /// Gas consommé par le bloc.
    pub gas_used: u64,
    /// Gas limite du bloc.
    pub gas_limit: u64,
}

impl BlockHeader {
    /// Calcule `block_hash` selon la formule normative :
    ///
    /// ```text
    /// block_hash = Keccak256("SANGO/BLOCK/HEADER/V1" || canonical(header))
    /// ```
    #[must_use]
    pub fn hash(&self) -> Hash32 {
        keccak256(&self.encode_to_vec_with_domain())
    }

    /// Encode `DOMAIN_BLOCK_HEADER_V1 || canonical(header)`.
    ///
    /// Utilisé par [`BlockHeader::hash`].
    #[must_use]
    pub fn encode_to_vec_with_domain(&self) -> Vec<u8> {
        let mut enc = Encoder::new();
        enc.write_raw(domain::BLOCK_HEADER_V1);
        self.encode(&mut enc);
        enc.into_bytes()
    }
}

impl Encode for BlockHeader {
    fn encode(&self, enc: &mut Encoder) {
        self.version.encode(enc);
        self.chain_id.encode(enc);
        self.epoch.encode(enc);
        self.height.encode(enc);
        self.round.encode(enc);
        self.previous_block_hash.encode(enc);
        self.timestamp.encode(enc);
        self.proposer_address.encode(enc);
        self.transaction_root.encode(enc);
        self.state_root.encode(enc);
        self.receipt_root.encode(enc);
        self.gas_used.encode(enc);
        self.gas_limit.encode(enc);
    }
}

impl Decode for BlockHeader {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, sango_codec::CodecError> {
        Ok(Self {
            version: u32::decode(dec)?,
            chain_id: ChainId32::decode(dec)?,
            epoch: Epoch::decode(dec)?,
            height: Height::decode(dec)?,
            round: Round::decode(dec)?,
            previous_block_hash: Hash32::decode(dec)?,
            timestamp: u64::decode(dec)?,
            proposer_address: NativeAddress::decode(dec)?,
            transaction_root: Hash32::decode(dec)?,
            state_root: Hash32::decode(dec)?,
            receipt_root: Hash32::decode(dec)?,
            gas_used: u64::decode(dec)?,
            gas_limit: u64::decode(dec)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> BlockHeader {
        BlockHeader {
            version: 1,
            chain_id: ChainId32::from_bytes([0x11; 32]),
            epoch: Epoch::new(0),
            height: Height::new(1),
            round: Round::new(0),
            previous_block_hash: Hash32::from_bytes([0x22; 32]),
            timestamp: 1_700_000_000,
            proposer_address: NativeAddress::from_bytes([0x33; 20]),
            transaction_root: Hash32::from_bytes([0x44; 32]),
            state_root: Hash32::from_bytes([0x55; 32]),
            receipt_root: Hash32::from_bytes([0x66; 32]),
            gas_used: 0,
            gas_limit: 30_000_000,
        }
    }

    #[test]
    fn header_roundtrip() {
        let h = sample();
        let bytes = h.encode_to_vec();
        let decoded = BlockHeader::decode_exact(&bytes).unwrap();
        assert_eq!(decoded, h);
    }

    #[test]
    fn header_encoding_size_is_fixed() {
        let bytes = sample().encode_to_vec();
        // 4 + 32 + 8 + 8 + 8 + 32 + 8 + 20 + 32 + 32 + 32 + 8 + 8 = 232
        assert_eq!(bytes.len(), 232);
    }

    #[test]
    fn hash_is_deterministic() {
        let h = sample();
        assert_eq!(h.hash(), h.hash());
    }

    #[test]
    fn hash_changes_with_field() {
        let mut h = sample();
        let a = h.hash();
        h.height = Height::new(2);
        assert_ne!(a, h.hash());
    }

    #[test]
    fn hash_uses_block_header_domain() {
        let h = sample();
        let mut canonical = Encoder::new();
        h.encode(&mut canonical);
        let expected = keccak256(&{
            let mut buf = Vec::new();
            buf.extend_from_slice(domain::BLOCK_HEADER_V1);
            buf.extend_from_slice(canonical.as_slice());
            buf
        });
        assert_eq!(h.hash(), expected);
    }
}
