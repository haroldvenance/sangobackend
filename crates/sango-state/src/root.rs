//! Combinaison du `native_state_root` et du `evm_state_root` en un
//! `state_root` global conforme au Freeze V1.

use sango_crypto::{domain, hash_domain_parts};
use sango_primitives::Hash32;

/// Calcule le `state_root` global selon la formule normative du Freeze :
///
/// ```text
/// state_root = Keccak256(
///     "SANGO/STATE/ROOT/V1"
///     || native_state_root
///     || evm_state_root
/// )
/// ```
///
/// Cette fonction est **purement déterministe** : les deux roots d'entrée
/// proviennent d'implémentations séparées (native et EVM), mais leur
/// combinaison est unique et canonique.
#[must_use]
pub fn global_state_root(native_state_root: Hash32, evm_state_root: Hash32) -> Hash32 {
    let parts: &[&[u8]] = &[
        &native_state_root.as_bytes()[..],
        &evm_state_root.as_bytes()[..],
    ];
    hash_domain_parts(domain::STATE_ROOT_V1, parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(b: u8) -> Hash32 {
        Hash32::from_bytes([b; 32])
    }

    #[test]
    fn global_root_is_deterministic() {
        let a = global_state_root(h(0x11), h(0x22));
        let b = global_state_root(h(0x11), h(0x22));
        assert_eq!(a, b);
    }

    #[test]
    fn global_root_depends_on_native() {
        let a = global_state_root(h(0x11), h(0x22));
        let b = global_state_root(h(0x12), h(0x22));
        assert_ne!(a, b);
    }

    #[test]
    fn global_root_depends_on_evm() {
        let a = global_state_root(h(0x11), h(0x22));
        let b = global_state_root(h(0x11), h(0x23));
        assert_ne!(a, b);
    }

    #[test]
    fn global_root_is_not_commutative() {
        let a = global_state_root(h(0x11), h(0x22));
        let b = global_state_root(h(0x22), h(0x11));
        assert_ne!(a, b);
    }

    #[test]
    fn global_root_zero_inputs() {
        let a = global_state_root(Hash32::ZERO, Hash32::ZERO);
        let b = global_state_root(Hash32::ZERO, Hash32::ZERO);
        assert_eq!(a, b);
        assert!(!a.is_zero());
    }
}
