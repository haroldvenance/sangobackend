//! Dérivation normative de `prevrandao` EVM.
//!
//! ## Formule (décision figée 4c)
//!
//! ```text
//! prevrandao = Keccak256("SANGO/EVM/PREVRANDAO/V1" || parent_block_hash)
//! ```
//!
//! Déterministe. Vérifiable par tout nœud à partir du header parent.
//! **Aucune source de hasard locale.**
//!
//! ## Consensus-critical
//!
//! `PREVRANDAO` est exposé aux contrats EVM (instruction `0x44`). Dès
//! qu'un contrat peut influencer son comportement par `prevrandao`, cette
//! dérivation devient une règle de consensus. Le vecteur de test
//! `vector_zero_parent` fige la valeur pour `parent_block_hash = 0`.

use sango_crypto::{domain, hash_domain};
use sango_primitives::Hash32;

/// Dérive `prevrandao` à partir du hash du bloc parent.
#[must_use]
pub fn derive_prevrandao(parent_block_hash: Hash32) -> Hash32 {
    hash_domain(domain::EVM_PREVRANDAO_V1, parent_block_hash.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let p = Hash32::from_bytes([0x42; 32]);
        assert_eq!(derive_prevrandao(p), derive_prevrandao(p));
    }

    #[test]
    fn changes_with_parent() {
        let p1 = Hash32::from_bytes([0x01; 32]);
        let p2 = Hash32::from_bytes([0x02; 32]);
        assert_ne!(derive_prevrandao(p1), derive_prevrandao(p2));
    }

    #[test]
    fn not_equal_to_parent_hash_itself() {
        let p = Hash32::from_bytes([0xaa; 32]);
        assert_ne!(derive_prevrandao(p), p);
    }

    /// Vecteur de test **normatif**.
    ///
    /// `parent_hash = 0x00...00` (32 zéros) →
    /// `prevrandao = Keccak256("SANGO/EVM/PREVRANDAO/V1" || 32 × 0x00)`.
    ///
    /// Ce vecteur fige la dérivation. Si un changement de domaine ou de
    /// formule casse ce test, c'est un **hard fork** à documenter.
    #[test]
    fn vector_zero_parent() {
        let p = Hash32::ZERO;
        let got = derive_prevrandao(p);
        let expected = {
            let mut buf = Vec::new();
            buf.extend_from_slice(b"SANGO/EVM/PREVRANDAO/V1");
            buf.extend_from_slice(&[0u8; 32]);
            sango_crypto::keccak256(&buf)
        };
        assert_eq!(got, expected);
    }
}
