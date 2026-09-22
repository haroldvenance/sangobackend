//! `ChainTip` : dernier bloc appliqué par un nœud.

use sango_codec::{CodecError, Decode, Decoder, Encode, Encoder};
use sango_primitives::{Hash32, Height};

/// Pointeur vers le dernier bloc appliqué.
///
/// Persisté dans le namespace `Metadata` sous `MetadataKey::ChainTip`.
/// Permet à un nœud de reprendre après redémarrage et de valider la
/// continuité de chaîne.
///
/// ## Encodage
///
/// ```text
/// height (u64 LE) || block_hash (32) || base_fee (u128 LE)
/// ```
///
/// Taille fixe : **56 bytes**.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ChainTip {
    /// Hauteur du dernier bloc appliqué.
    pub height: Height,
    /// Hash du dernier bloc appliqué.
    pub block_hash: Hash32,
    /// Base fee utilisée par ce bloc. Utile pour calculer la base fee du
    /// bloc suivant.
    pub base_fee: u128,
}

impl Encode for ChainTip {
    fn encode(&self, enc: &mut Encoder) {
        self.height.encode(enc);
        self.block_hash.encode(enc);
        self.base_fee.encode(enc);
    }
}

impl Decode for ChainTip {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            height: Height::decode(dec)?,
            block_hash: Hash32::decode(dec)?,
            base_fee: u128::decode(dec)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ChainTip {
        ChainTip {
            height: Height::new(42),
            block_hash: Hash32::from_bytes([0xab; 32]),
            base_fee: 1_000_000,
        }
    }

    #[test]
    fn roundtrip() {
        let t = sample();
        let bytes = t.encode_to_vec();
        assert_eq!(bytes.len(), 56);
        assert_eq!(ChainTip::decode_exact(&bytes).unwrap(), t);
    }

    #[test]
    fn encoding_size_is_fixed() {
        assert_eq!(sample().encode_to_vec().len(), 56);
    }
}
