//! Lecteur binaire pour l'encodage canonique.

use crate::{CodecError, Decode};

/// Lecteur binaire canonique avec position courante.
#[derive(Debug, Clone)]
pub struct Decoder<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    /// Crée un décodeur sur une slice.
    #[must_use]
    pub fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    /// Position courante.
    #[must_use]
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Bytes encore disponibles.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.pos)
    }

    /// Vrai si tout a été consommé.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Vérifie que tout a été consommé, sinon renvoie [`CodecError::TrailingBytes`].
    pub fn finish(self) -> Result<(), CodecError> {
        if self.remaining() > 0 {
            return Err(CodecError::TrailingBytes {
                position: self.pos,
                count: self.remaining(),
            });
        }
        Ok(())
    }

    /// Lit `n` bytes bruts.
    pub fn read_raw(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        let end = self.pos.checked_add(n).ok_or(CodecError::UnexpectedEof {
            position: self.pos,
            needed: n,
            remaining: self.remaining(),
        })?;
        if end > self.input.len() {
            return Err(CodecError::UnexpectedEof {
                position: self.pos,
                needed: n,
                remaining: self.remaining(),
            });
        }
        let slice = &self.input[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    /// Lit un tableau fixe de `N` bytes.
    pub fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        let raw = self.read_raw(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(raw);
        Ok(out)
    }

    /// Lit un `u8`.
    pub fn read_u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.read_fixed::<1>()?[0])
    }

    /// Lit un `u16` little-endian.
    pub fn read_u16_le(&mut self) -> Result<u16, CodecError> {
        Ok(u16::from_le_bytes(self.read_fixed::<2>()?))
    }

    /// Lit un `u32` little-endian.
    pub fn read_u32_le(&mut self) -> Result<u32, CodecError> {
        Ok(u32::from_le_bytes(self.read_fixed::<4>()?))
    }

    /// Lit un `u64` little-endian.
    pub fn read_u64_le(&mut self) -> Result<u64, CodecError> {
        Ok(u64::from_le_bytes(self.read_fixed::<8>()?))
    }

    /// Lit un `u128` little-endian.
    pub fn read_u128_le(&mut self) -> Result<u128, CodecError> {
        Ok(u128::from_le_bytes(self.read_fixed::<16>()?))
    }

    /// Lit des bytes préfixés par un `u32` little-endian.
    pub fn read_bytes(&mut self) -> Result<Vec<u8>, CodecError> {
        let len = self.read_u32_le()? as usize;
        if len > self.remaining() {
            return Err(CodecError::InvalidLength {
                declared: len as u64,
                remaining: self.remaining(),
            });
        }
        Ok(self.read_raw(len)?.to_vec())
    }

    /// Lit un compteur d'éléments (`u32` little-endian) et décode `count` éléments.
    ///
    /// Le buffer d'allocation initial est plafonné pour éviter une allocation
    /// massive sur une entrée malformée.
    pub fn read_vec<T: Decode>(&mut self) -> Result<Vec<T>, CodecError> {
        let count = self.read_u32_le()? as usize;
        if count > self.remaining() {
            return Err(CodecError::InvalidLength {
                declared: count as u64,
                remaining: self.remaining(),
            });
        }
        let mut out = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            out.push(T::decode(self)?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::Decoder;
    use crate::CodecError;

    #[test]
    fn read_u16_le_order() {
        let mut d = Decoder::new(&[0x02, 0x01]);
        assert_eq!(d.read_u16_le().unwrap(), 0x0102);
        assert!(d.is_empty());
    }

    #[test]
    fn read_u32_le_order() {
        let mut d = Decoder::new(&[0x04, 0x03, 0x02, 0x01]);
        assert_eq!(d.read_u32_le().unwrap(), 0x01020304);
    }

    #[test]
    fn read_u64_le_order() {
        let mut d = Decoder::new(&[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
        assert_eq!(d.read_u64_le().unwrap(), 0x0102030405060708);
    }

    #[test]
    fn read_u128_le_order() {
        let bytes = [
            0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03,
            0x02, 0x01,
        ];
        let mut d = Decoder::new(&bytes);
        assert_eq!(
            d.read_u128_le().unwrap(),
            0x0102030405060708090a0b0c0d0e0f10
        );
    }

    #[test]
    fn unexpected_eof() {
        let mut d = Decoder::new(&[0x01, 0x02]);
        let err = d.read_u32_le().unwrap_err();
        assert!(matches!(err, CodecError::UnexpectedEof { .. }));
    }

    #[test]
    fn finish_rejects_trailing_bytes() {
        let d = Decoder::new(&[0x00, 0x00]);
        let err = d.finish().unwrap_err();
        assert!(matches!(err, CodecError::TrailingBytes { count: 2, .. }));
    }

    #[test]
    fn read_bytes_prefix() {
        let mut d = Decoder::new(&[0x03, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc]);
        assert_eq!(d.read_bytes().unwrap(), vec![0xaa, 0xbb, 0xcc]);
        d.finish().unwrap();
    }

    #[test]
    fn read_bytes_length_exceeds_remaining() {
        let mut d = Decoder::new(&[0xff, 0x00, 0x00, 0x00, 0x01]);
        let err = d.read_bytes().unwrap_err();
        assert!(matches!(
            err,
            CodecError::InvalidLength { declared: 255, .. }
        ));
    }

    #[test]
    fn read_vec_caps_alloc() {
        // count = u32::MAX, remaining = 0 → InvalidLength (pas d'alloc)
        let mut d = Decoder::new(&[0xff, 0xff, 0xff, 0xff]);
        let err = d.read_vec::<u8>().unwrap_err();
        assert!(matches!(err, CodecError::InvalidLength { .. }));
    }
}
