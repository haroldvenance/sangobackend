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

use sango_primitives::{NativeAddress, PublicKey};

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
}
