//! Implémentations `Encode`/`Decode` pour les types standard et primitives.

use sango_primitives::{
    Amount, ChainId32, Epoch, EvmAddress, EvmChainId, Hash32, Height, NativeAddress, Round,
};

use crate::{CodecError, Decode, Decoder, Encode, Encoder};

// --- Entiers ----------------------------------------------------------------

impl Encode for u8 {
    fn encode(&self, enc: &mut Encoder) {
        enc.write_u8(*self);
    }
}

impl Decode for u8 {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        dec.read_u8()
    }
}

impl Encode for u16 {
    fn encode(&self, enc: &mut Encoder) {
        enc.write_u16_le(*self);
    }
}

impl Decode for u16 {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        dec.read_u16_le()
    }
}

impl Encode for u32 {
    fn encode(&self, enc: &mut Encoder) {
        enc.write_u32_le(*self);
    }
}

impl Decode for u32 {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        dec.read_u32_le()
    }
}

impl Encode for u64 {
    fn encode(&self, enc: &mut Encoder) {
        enc.write_u64_le(*self);
    }
}

impl Decode for u64 {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        dec.read_u64_le()
    }
}

impl Encode for u128 {
    fn encode(&self, enc: &mut Encoder) {
        enc.write_u128_le(*self);
    }
}

impl Decode for u128 {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        dec.read_u128_le()
    }
}

// --- Tableaux fixes ---------------------------------------------------------

impl<const N: usize> Encode for [u8; N] {
    fn encode(&self, enc: &mut Encoder) {
        enc.write_raw(self);
    }
}

impl<const N: usize> Decode for [u8; N] {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        dec.read_fixed::<N>()
    }
}

// --- Vecteurs ---------------------------------------------------------------

/// `Vec<T>` → `u32 count || elements`.
///
/// Pour `T = u8`, ceci équivaut à `u32 length || bytes`, ce qui est exactement
/// la représentation canonique des bytes variables.
impl<T: Encode> Encode for Vec<T> {
    fn encode(&self, enc: &mut Encoder) {
        enc.write_count(self.len());
        for item in self {
            item.encode(enc);
        }
    }
}

impl<T: Decode> Decode for Vec<T> {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        dec.read_vec()
    }
}

// --- Options (tag u8 : 0 = None, 1 = Some) ----------------------------------

impl<T: Encode> Encode for Option<T> {
    fn encode(&self, enc: &mut Encoder) {
        match self {
            None => enc.write_u8(0),
            Some(v) => {
                enc.write_u8(1);
                v.encode(enc);
            }
        }
    }
}

impl<T: Decode> Decode for Option<T> {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let tag = dec.read_u8()?;
        match tag {
            0 => Ok(None),
            1 => Ok(Some(T::decode(dec)?)),
            other => Err(CodecError::InvalidTag { tag: other }),
        }
    }
}

// --- Newtypes à taille fixe (sango-primitives) ------------------------------

macro_rules! impl_fixed_bytes {
    ($ty:ty, $n:expr) => {
        impl Encode for $ty {
            fn encode(&self, enc: &mut Encoder) {
                enc.write_raw(self.as_bytes());
            }
        }

        impl Decode for $ty {
            fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
                let raw = dec.read_fixed::<$n>()?;
                Ok(Self::from_bytes(raw))
            }
        }
    };
}

impl_fixed_bytes!(Hash32, 32);
impl_fixed_bytes!(ChainId32, 32);
impl_fixed_bytes!(NativeAddress, 20);
impl_fixed_bytes!(EvmAddress, 20);

// --- Newtypes numériques ----------------------------------------------------

macro_rules! impl_u64_newtype {
    ($ty:ty) => {
        impl Encode for $ty {
            fn encode(&self, enc: &mut Encoder) {
                enc.write_u64_le(self.get());
            }
        }

        impl Decode for $ty {
            fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
                Ok(Self::new(dec.read_u64_le()?))
            }
        }
    };
}

impl_u64_newtype!(Height);
impl_u64_newtype!(Round);
impl_u64_newtype!(Epoch);
impl_u64_newtype!(EvmChainId);

// --- Amount (u128 LE) -------------------------------------------------------

impl Encode for Amount {
    fn encode(&self, enc: &mut Encoder) {
        enc.write_u128_le(self.base_units());
    }
}

impl Decode for Amount {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self::from_base_units(dec.read_u128_le()?))
    }
}

// --- Clés et signatures -----------------------------------------------------

impl_fixed_bytes!(sango_primitives::PublicKey, 32);
impl_fixed_bytes!(sango_primitives::Signature, 64);

// --- Booléens (tag u8 : 0 = false, 1 = true) --------------------------------

impl Encode for bool {
    fn encode(&self, enc: &mut Encoder) {
        enc.write_u8(u8::from(*self));
    }
}

impl Decode for bool {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        match dec.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(CodecError::InvalidTag { tag: other }),
        }
    }
}
