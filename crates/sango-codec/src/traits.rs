//! Traits `Encode` et `Decode`.

use crate::{Decoder, Encoder};

/// Types encodables en binaire canonique Sango.
pub trait Encode {
    /// Écrit la représentation canonique dans `enc`.
    fn encode(&self, enc: &mut Encoder);

    /// Raccourci : encode dans un nouveau `Vec<u8>`.
    #[must_use]
    fn encode_to_vec(&self) -> Vec<u8> {
        let mut enc = Encoder::new();
        self.encode(&mut enc);
        enc.into_bytes()
    }
}

/// Types décodables depuis le binaire canonique Sango.
pub trait Decode: Sized {
    /// Lit la représentation canonique depuis `dec`.
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, crate::CodecError>;

    /// Raccourci : décode depuis une slice **et exige** que tout soit consommé.
    fn decode_exact(input: &[u8]) -> Result<Self, crate::CodecError> {
        let mut dec = Decoder::new(input);
        let value = Self::decode(&mut dec)?;
        dec.finish()?;
        Ok(value)
    }
}
