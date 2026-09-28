//! Dérivation d'adresses natives Sango.
//!
//! ## Formule normative (Freeze, section 8)
//!
//! ```text
//! Address20 = Keccak256("SANGO/ADDRESS/V1" || public_key)[0..20]
//! ```
//!
//! Invariants :
//!
//! - `PublicKey` : clé publique Ed25519, **exactement 32 bytes** ;
//! - `Address20` : **exactement 20 bytes** ;
//! - Hash : **Keccak-256** (pas SHA3-256) ;
//! - Préfixe : **exactement** `"SANGO/ADDRESS/V1"` (ASCII, pas de
//!   terminateur).
//!
//! ## Bech32m
//!
//! **Aucune étape Bech32m n'est impliquée dans la dérivation.** Bech32m est
//! uniquement la représentation utilisateur de l'adresse native
//! (`sango1...` / `tsango1...`). Le consensus manipule les 20 bytes bruts.
//!
//! ```text
//! public_key
//!     ↓
//! Keccak256(domain || public_key)
//!     ↓
//! first 20 bytes
//!     ↓
//! Address20          ← donnée de consensus
//!     ↓
//! Bech32m            ← affichage utilisateur uniquement
//! ```

use sango_primitives::{EvmAddress, NativeAddress, PublicKey};

use crate::{domain, hash_domain};

/// Dérive une adresse native Sango depuis une clé publique Ed25519.
///
/// Formule exacte :
///
/// ```text
/// Address20 = Keccak256("SANGO/ADDRESS/V1" || public_key)[0..20]
/// ```
///
/// Aucune étape Bech32m. Aucune autre transformation.
#[must_use]
pub fn derive_native_address(public_key: &PublicKey) -> NativeAddress {
    let h = hash_domain(domain::ADDRESS_V1, public_key.as_bytes());
    let mut bytes = [0u8; 20];
    bytes.copy_from_slice(&h.as_bytes()[..20]);
    NativeAddress::from_bytes(bytes)
}

/// Formate une adresse EVM en **checksum EIP-55**.
///
/// ## Spécification (EIP-55)
///
/// ```text
/// lower = hex(addr) sans 0x           (40 chars lowercase)
/// hash  = Keccak256(lower_ascii)      (32 bytes)
/// pour chaque nibble i de `hash` :
///   si `lower[i]` est une lettre (a-f) :
///     si nibble_i >= 8 : uppercase
///     sinon : lowercase
/// ```
///
/// Retourne `0x` + 40 chars mixed-case.
///
/// ## Usage
///
/// MetaMask, Hardhat, ethers.js et la majorité des outils Ethereum
/// affichent les adresses en EIP-55. C'est le format recommandé pour
/// l'affichage utilisateur (permet de détecter visuellement une
/// adresse mal recopiée).
#[must_use]
pub fn evm_checksum_hex(addr: &EvmAddress) -> String {
    // `to_hex()` retourne du lowercase sans préfixe `0x`, exactement
    // ce qu'on veut pour EIP-55.
    let lower = addr.to_hex();
    let hash = crate::keccak256(lower.as_bytes());
    let hash_hex = hash.to_hex();

    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in lower.chars().enumerate() {
        if c.is_ascii_alphabetic() {
            // Le nibble i du hash : caractère hex à la position i.
            let nibble =
                u8::from_str_radix(&hash_hex[i..i + 1], 16).expect("hash_hex is valid hex");
            if nibble >= 8 {
                out.push(c.to_ascii_uppercase());
            } else {
                out.push(c);
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed25519::NativeKeypair;

    #[test]
    fn address_is_exactly_20_bytes() {
        let pk = PublicKey::from_bytes([0x11; 32]);
        assert_eq!(derive_native_address(&pk).as_bytes().len(), 20);
    }

    #[test]
    fn derivation_is_deterministic() {
        let pk = PublicKey::from_bytes([0x11; 32]);
        assert_eq!(derive_native_address(&pk), derive_native_address(&pk));
    }

    #[test]
    fn different_keys_give_different_addresses() {
        let pk1 = PublicKey::from_bytes([0x11; 32]);
        let pk2 = PublicKey::from_bytes([0x22; 32]);
        assert_ne!(derive_native_address(&pk1), derive_native_address(&pk2));
    }

    #[test]
    fn matches_manual_keccak_prefix() {
        // Vecteur de contrôle : on recalcule manuellement la formule
        // et on vérifie que la fonction retourne exactement les 20 premiers
        // bytes du hash.
        let pk = PublicKey::from_bytes([0x42; 32]);
        let mut buf = Vec::new();
        buf.extend_from_slice(domain::ADDRESS_V1);
        buf.extend_from_slice(pk.as_bytes());
        let h = crate::keccak256(&buf);

        let mut expected = [0u8; 20];
        expected.copy_from_slice(&h.as_bytes()[..20]);
        assert_eq!(
            derive_native_address(&pk),
            NativeAddress::from_bytes(expected)
        );
    }

    #[test]
    fn domain_prefix_is_normative() {
        // Vérifie que le préfixe utilisé est bien "SANGO/ADDRESS/V1".
        assert_eq!(domain::ADDRESS_V1, b"SANGO/ADDRESS/V1");
    }

    #[test]
    fn keypair_derivation_is_stable() {
        let kp = NativeKeypair::from_seed([0x55; 32]);
        let pk = kp.public_key();
        assert_eq!(derive_native_address(&pk), derive_native_address(&pk));
    }

    // --- EIP-55 checksum -------------------------------------------------

    /// Vecteur officiel EIP-55.
    #[test]
    fn eip55_known_vectors() {
        use sango_primitives::EvmAddress;

        // EIP-55 spec examples (from the EIP document).
        let cases: &[(&str, &str)] = &[
            (
                "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
                "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            ),
            (
                "0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359",
                "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            ),
            (
                "0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb",
                "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            ),
            (
                "0xd1220a0cf47c7b9be7a2e6ba89f429762e7b9adb",
                "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
            ),
        ];

        for (lower, checksummed) in cases {
            let addr = EvmAddress::from_hex(lower).unwrap();
            assert_eq!(
                evm_checksum_hex(&addr),
                *checksummed,
                "EIP-55 mismatch for {lower}"
            );
        }
    }

    #[test]
    fn eip55_deterministic() {
        let addr = EvmAddress::from_bytes([0xaa; 20]);
        assert_eq!(evm_checksum_hex(&addr), evm_checksum_hex(&addr));
    }

    #[test]
    fn eip55_starts_with_0x_and_len_42() {
        let addr = EvmAddress::from_bytes([0xab; 20]);
        let s = evm_checksum_hex(&addr);
        assert!(s.starts_with("0x"));
        assert_eq!(s.len(), 42);
    }

    #[test]
    fn eip55_lowercase_compare() {
        // Le lowercase et le checksum dérivent de la même adresse.
        let addr = EvmAddress::from_bytes([0xcd; 20]);
        let checksummed = evm_checksum_hex(&addr);
        let lower = format!("0x{}", addr.to_hex());
        assert_eq!(checksummed.to_lowercase(), lower);
    }
}
