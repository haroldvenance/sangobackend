//! Écrivain binaire pour l'encodage canonique.

/// Écrivain binaire canonique.
///
/// Ne gère que l'écriture : il n'effectue aucune validation au-delà des
/// limites du buffer sous-jacent.
#[derive(Debug, Default, Clone)]
pub struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    /// Crée un encodeur vide.
    #[must_use]
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Crée un encodeur avec une capacité initiale.
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }

    /// Nombre de bytes écrits.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Vrai si rien n'a été écrit.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Vue empruntée sur les bytes écrits.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Consomme l'encodeur et retourne le buffer.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Écrit un `u8` brut (1 byte).
    pub fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    /// Écrit un `u16` en little-endian (2 bytes).
    pub fn write_u16_le(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Écrit un `u32` en little-endian (4 bytes).
    pub fn write_u32_le(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Écrit un `u64` en little-endian (8 bytes).
    pub fn write_u64_le(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Écrit un `u128` en little-endian (16 bytes).
    pub fn write_u128_le(&mut self, v: u128) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Écrit des bytes bruts **sans** préfixe de longueur.
    pub fn write_raw(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Écrit des bytes préfixés par un `u32` little-endian (longueur).
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        let len = bytes.len() as u64;
        let len_u32 = u32::try_from(len).expect("byte length exceeds u32::MAX");
        self.write_u32_le(len_u32);
        self.write_raw(bytes);
    }

    /// Écrit un compteur d'éléments (`u32` little-endian).
    pub fn write_count(&mut self, count: usize) {
        let c = u32::try_from(count).expect("element count exceeds u32::MAX");
        self.write_u32_le(c);
    }
}

#[cfg(test)]
mod tests {
    use super::Encoder;

    #[test]
    fn empty() {
        let e = Encoder::new();
        assert!(e.is_empty());
        assert_eq!(e.len(), 0);
        assert!(e.into_bytes().is_empty());
    }

    #[test]
    fn u16_le_order() {
        let mut e = Encoder::new();
        e.write_u16_le(0x0102);
        assert_eq!(e.as_slice(), &[0x02, 0x01]);
    }

    #[test]
    fn u32_le_order() {
        let mut e = Encoder::new();
        e.write_u32_le(0x01020304);
        assert_eq!(e.as_slice(), &[0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn u64_le_order() {
        let mut e = Encoder::new();
        e.write_u64_le(0x0102030405060708);
        assert_eq!(
            e.as_slice(),
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
    }

    #[test]
    fn u128_le_order() {
        let mut e = Encoder::new();
        e.write_u128_le(0x0102030405060708090a0b0c0d0e0f10);
        assert_eq!(
            e.as_slice(),
            &[
                0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03,
                0x02, 0x01
            ]
        );
    }

    #[test]
    fn bytes_prefixes_with_u32_le() {
        let mut e = Encoder::new();
        e.write_bytes(&[0xaa, 0xbb, 0xcc]);
        assert_eq!(e.as_slice(), &[0x03, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn empty_bytes_prefix() {
        let mut e = Encoder::new();
        e.write_bytes(&[]);
        assert_eq!(e.as_slice(), &[0x00, 0x00, 0x00, 0x00]);
    }
}
