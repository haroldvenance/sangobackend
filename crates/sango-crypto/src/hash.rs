//! Hash natif Sango : Keccak-256.

use sango_primitives::Hash32;
use sha3::{Digest, Keccak256};

/// Calcule `Keccak256(data)`.
///
/// **Attention** : il s’agit de **Keccak** (padding `0x01`), pas de la
/// variante NIST SHA3-256 (padding `0x06`).
#[must_use]
pub fn keccak256(data: &[u8]) -> Hash32 {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    Hash32::from_bytes(buf)
}

/// Calcule `Keccak256(domain || payload)`.
///
/// C’est la construction canonique pour tous les hashes de protocole.
#[must_use]
pub fn hash_domain(domain: &[u8], payload: &[u8]) -> Hash32 {
    let mut hasher = Keccak256::new();
    hasher.update(domain);
    hasher.update(payload);
    let out = hasher.finalize();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    Hash32::from_bytes(buf)
}

/// Calcule `Keccak256(domain || p0 || p1 || ...)`.
///
/// Utile quand le payload est naturellement composé de plusieurs morceaux
/// (par exemple `chain_id || epoch || height || round || block_hash`).
#[must_use]
pub fn hash_domain_parts(domain: &[u8], parts: &[&[u8]]) -> Hash32 {
    let mut hasher = Keccak256::new();
    hasher.update(domain);
    for p in parts {
        hasher.update(p);
    }
    let out = hasher.finalize();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    Hash32::from_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn keccak256_empty() {
        // Vecteur bien connu : keccak256("") =
        // c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        let expected = hex!(
            "c5d2460186f7233c927e7db2dcc703c0"
            "e500b653ca82273b7bfad8045d85a470"
        );
        assert_eq!(keccak256(b"").to_bytes(), expected);
    }

    #[test]
    fn keccak256_abc() {
        // keccak256("abc") =
        // 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
        let expected = hex!(
            "4e03657aea45a94fc7d47ba826c8d667"
            "c0d1e6e33a64a036ec44f58fa12d6c45"
        );
        assert_eq!(keccak256(b"abc").to_bytes(), expected);
    }

    #[test]
    fn hash_domain_is_prefix_sensitive() {
        let a = hash_domain(b"SANGO/TX/V1", b"payload");
        let b = hash_domain(b"SANGO/BLOCK/HEADER/V1", b"payload");
        assert_ne!(a, b);
    }

    #[test]
    fn hash_domain_matches_manual_concat() {
        let a = hash_domain(b"SANGO/TX/V1", b"hello");
        let mut buf = Vec::new();
        buf.extend_from_slice(b"SANGO/TX/V1");
        buf.extend_from_slice(b"hello");
        let b = keccak256(&buf);
        assert_eq!(a, b);
    }

    #[test]
    fn hash_domain_parts_matches_manual_concat() {
        let parts: &[&[u8]] = &[b"a", b"bc", b"def"];
        let a = hash_domain_parts(b"SANGO/TX/V1", parts);
        let b = hash_domain(b"SANGO/TX/V1", b"abcdef");
        assert_eq!(a, b);
    }

    #[test]
    fn keccak256_is_deterministic() {
        let a = keccak256(b"hello world");
        let b = keccak256(b"hello world");
        assert_eq!(a, b);
    }
}
