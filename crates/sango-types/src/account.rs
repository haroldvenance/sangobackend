//! Compte natif Sango.

use sango_codec::{CodecError, Decode, Decoder, Encode, Encoder};
use sango_primitives::{Amount, NativeAddress};

/// Compte natif Sango V1.
///
/// `balance` est exprimée en base units (`u128`).
/// `nonce` est un `u64` strictement croissant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Default)]
pub struct Account {
    /// Adresse native.
    pub address: NativeAddress,
    /// Solde en base units.
    pub balance: Amount,
    /// Compteur de transactions émises.
    pub nonce: u64,
}

impl Encode for Account {
    fn encode(&self, enc: &mut Encoder) {
        self.address.encode(enc);
        self.balance.encode(enc);
        self.nonce.encode(enc);
    }
}

impl Decode for Account {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            address: NativeAddress::decode(dec)?,
            balance: Amount::decode(dec)?,
            nonce: u64::decode(dec)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_roundtrip() {
        let a = Account {
            address: NativeAddress::from_bytes([0x11; 20]),
            balance: Amount::from_base_units(10_000_000),
            nonce: 42,
        };
        let bytes = a.encode_to_vec();
        let decoded = Account::decode_exact(&bytes).unwrap();
        assert_eq!(decoded, a);
    }

    #[test]
    fn account_encoding_size_is_fixed() {
        let a = Account {
            address: NativeAddress::from_bytes([0x11; 20]),
            balance: Amount::from_base_units(0),
            nonce: 0,
        };
        // 20 (address) + 16 (u128 balance) + 8 (u64 nonce) = 44
        assert_eq!(a.encode_to_vec().len(), 44);
    }
}
