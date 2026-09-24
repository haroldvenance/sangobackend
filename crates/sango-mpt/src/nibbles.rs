//! Conversions bytes ↔ nibbles et hex-prefix encoding (Ethereum).

use crate::error::MptError;

/// Convertit une séquence de bytes en nibbles (chaque byte → 2 nibbles, MSB first).
#[must_use]
pub fn bytes_to_nibbles(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(b >> 4);
        out.push(b & 0x0F);
    }
    out
}

/// Convertit une séquence de nibbles (longueur paire) en bytes.
#[must_use]
pub fn nibbles_to_bytes(nibbles: &[u8]) -> Vec<u8> {
    debug_assert!(nibbles.len().is_multiple_of(2));
    let mut out = Vec::with_capacity(nibbles.len() / 2);
    for chunk in nibbles.as_chunks::<2>().0 {
        out.push((chunk[0] << 4) | (chunk[1] & 0x0F));
    }
    out
}

/// Hex-prefix encoding (Ethereum yellowpaper, Appendix C).
///
/// Le premier nibble du premier byte encode `(is_leaf << 1) | (len(path) % 2)` :
///
/// - feuille, longueur paire  → premier nibble `2` ;
/// - feuille, longueur impaire → premier nibble `3` ;
/// - extension, longueur paire → premier nibble `0` ;
/// - extension, longueur impaire → premier nibble `1`.
///
/// Si `path.len()` est impair, le premier nibble du chemin occupe le
/// second nibble du premier byte.
#[must_use]
pub fn hex_prefix(path: &[u8], is_leaf: bool) -> Vec<u8> {
    let flag: u8 = u8::from(is_leaf);
    let odd = !path.len().is_multiple_of(2);
    let first_nibble = (flag << 1) | u8::from(odd);

    let mut out = Vec::with_capacity(1 + path.len() / 2);
    if odd {
        out.push((first_nibble << 4) | (path[0] & 0x0F));
        for i in (1..path.len()).step_by(2) {
            out.push((path[i] << 4) | (path[i + 1] & 0x0F));
        }
    } else {
        out.push(first_nibble << 4);
        for i in (0..path.len()).step_by(2) {
            out.push((path[i] << 4) | (path[i + 1] & 0x0F));
        }
    }
    out
}

/// Inverse de [`hex_prefix`] : retourne `(path_nibbles, is_leaf)`.
pub fn from_hex_prefix(bytes: &[u8]) -> Result<(Vec<u8>, bool), MptError> {
    if bytes.is_empty() {
        return Err(MptError::InvalidHexPrefix);
    }
    let first = bytes[0];
    let first_nibble = first >> 4;
    if first_nibble > 3 {
        return Err(MptError::InvalidHexPrefix);
    }
    let is_leaf = (first_nibble & 0b10) != 0;
    let odd = (first_nibble & 0b01) == 1;

    let mut out = Vec::with_capacity(bytes.len() * 2);
    if odd {
        out.push(first & 0x0F);
    }
    for b in &bytes[1..] {
        out.push(b >> 4);
        out.push(b & 0x0F);
    }
    Ok((out, is_leaf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_to_nibbles_basic() {
        assert_eq!(bytes_to_nibbles(&[0xab, 0xcd]), vec![0xa, 0xb, 0xc, 0xd]);
        assert_eq!(bytes_to_nibbles(&[]), Vec::<u8>::new());
        assert_eq!(bytes_to_nibbles(&[0x00]), vec![0x0, 0x0]);
    }

    #[test]
    fn nibbles_to_bytes_roundtrip() {
        let bytes = vec![0xab, 0xcd, 0xef];
        let nibbles = bytes_to_nibbles(&bytes);
        assert_eq!(nibbles_to_bytes(&nibbles), bytes);
    }

    #[test]
    fn hex_prefix_leaf_even() {
        assert_eq!(hex_prefix(&[1, 2, 3, 4], true), vec![0x20, 0x12, 0x34]);
    }

    #[test]
    fn hex_prefix_leaf_odd() {
        assert_eq!(hex_prefix(&[1, 2, 3], true), vec![0x31, 0x23]);
    }

    #[test]
    fn hex_prefix_extension_even() {
        assert_eq!(hex_prefix(&[1, 2, 3, 4], false), vec![0x00, 0x12, 0x34]);
    }

    #[test]
    fn hex_prefix_extension_odd() {
        assert_eq!(hex_prefix(&[1, 2, 3], false), vec![0x11, 0x23]);
    }

    #[test]
    fn hex_prefix_empty_leaf() {
        assert_eq!(hex_prefix(&[], true), vec![0x20]);
    }

    #[test]
    fn hex_prefix_empty_extension() {
        assert_eq!(hex_prefix(&[], false), vec![0x00]);
    }

    #[test]
    fn from_hex_prefix_roundtrip() {
        for (path, is_leaf) in [
            (vec![1, 2, 3, 4], true),
            (vec![1, 2, 3], true),
            (vec![1, 2, 3, 4], false),
            (vec![1, 2, 3], false),
            (vec![], true),
            (vec![], false),
        ] {
            let encoded = hex_prefix(&path, is_leaf);
            let (decoded_path, decoded_leaf) = from_hex_prefix(&encoded).unwrap();
            assert_eq!(decoded_path, path);
            assert_eq!(decoded_leaf, is_leaf);
        }
    }
}
