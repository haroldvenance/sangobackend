//! Storage trie par compte (Ethereum).
//!
//! ## Formule normative
//!
//! Un storage trie est un **MPT Ethereum** par compte :
//!
//! - **clé MPT** : `Keccak256(slot.to_be_bytes::<32>())` ;
//! - **valeur** : `RLP(value_minimal_be)`.
//!
//! Un slot dont la valeur est `0` n'est **pas** présent dans le trie
//! (Ethereum ne stocke pas les slots nuls). Cela implique qu'un slot
//! absent et un slot à zéro sont **sémantiquement équivalents** au niveau
//! du protocole.
//!
//! ## Préfixe physique RocksDB
//!
//! Le préfixe `Keccak256(evm_address)` dans RocksDB est **purement
//! physique** — il identifie le compte propriétaire du slot dans le KV
//! store. Il ne fait **pas** partie de la clé du storage MPT.

use std::collections::BTreeMap;

use rlp::RlpStream;
use sango_crypto::keccak256;
use sango_primitives::{Hash32, U256};

use crate::account::{append_u256_minimal, decode_u256};
use crate::error::EvmError;

/// Encodage RLP d'une valeur de storage.
#[must_use]
pub fn encode_storage_value(value: U256) -> Vec<u8> {
    let mut s = RlpStream::new();
    append_u256_minimal(&mut s, value);
    s.out().to_vec()
}

/// Décodage RLP d'une valeur de storage.
pub fn decode_storage_value(bytes: &[u8]) -> Result<U256, EvmError> {
    let rlp = rlp::Rlp::new(bytes);
    if !rlp.is_data() {
        return Err(EvmError::MalformedRlp);
    }
    decode_u256(&rlp)
}

/// Convertit un slot `U256` en clé de MPT `Keccak256(slot_be_32)`.
#[must_use]
pub fn slot_mpt_key(slot: U256) -> Hash32 {
    keccak256(&slot.to_be_bytes::<32>())
}

/// Storage trie en mémoire pour un compte.
///
/// Maps `Keccak256(slot_be_32)` → `RLP(value_minimal_be)`.
/// Les slots nuls ne sont pas présents.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StorageTrie {
    slots: BTreeMap<Hash32, Vec<u8>>,
}

impl StorageTrie {
    /// Trie vide.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Nombre de slots non-nuls.
    #[must_use]
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Vrai si le trie est vide.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Lit la valeur d'un slot. Retourne `U256::ZERO` si absent (ce qui
    /// correspond au comportement Ethereum).
    #[must_use]
    pub fn get(&self, slot: U256) -> U256 {
        let key = slot_mpt_key(slot);
        match self.slots.get(&key) {
            Some(rlp) => decode_storage_value(rlp).unwrap_or(U256::ZERO),
            None => U256::ZERO,
        }
    }

    /// Écrit un slot. `value == 0` supprime l'entrée (Ethereum).
    pub fn set(&mut self, slot: U256, value: U256) {
        let key = slot_mpt_key(slot);
        if value == U256::ZERO {
            self.slots.remove(&key);
        } else {
            self.slots.insert(key, encode_storage_value(value));
        }
    }

    /// Racine MPT du trie.
    #[must_use]
    pub fn root(&self) -> Hash32 {
        let entries: Vec<(Vec<u8>, Vec<u8>)> = self
            .slots
            .iter()
            .map(|(k, v)| (k.as_bytes().to_vec(), v.clone()))
            .collect();
        sango_mpt::mpt_root(&entries)
    }

    /// Itère sur les entrées `(slot_hash, rlp_value)`.
    pub fn iter_entries(&self) -> impl Iterator<Item = (&Hash32, &Vec<u8>)> {
        self.slots.iter()
    }

    /// Restaure une entrée brute (usage : chargement RocksDB).
    pub fn restore_entry(&mut self, slot_hash: Hash32, value: Vec<u8>) {
        self.slots.insert(slot_hash, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_trie_has_empty_root() {
        let t = StorageTrie::new();
        assert!(t.is_empty());
        assert_eq!(t.root(), sango_mpt::empty_root());
    }

    #[test]
    fn slot_absent_is_zero() {
        let t = StorageTrie::new();
        assert_eq!(t.get(U256::from(42u64)), U256::ZERO);
    }

    #[test]
    fn set_get_roundtrip() {
        let mut t = StorageTrie::new();
        t.set(U256::from(1u64), U256::from(100u64));
        t.set(U256::from(2u64), U256::from(200u64));
        assert_eq!(t.get(U256::from(1u64)), U256::from(100u64));
        assert_eq!(t.get(U256::from(2u64)), U256::from(200u64));
        assert_eq!(t.get(U256::from(3u64)), U256::ZERO);
    }

    #[test]
    fn set_zero_removes_slot() {
        let mut t = StorageTrie::new();
        t.set(U256::from(1u64), U256::from(100u64));
        assert_eq!(t.len(), 1);
        t.set(U256::from(1u64), U256::ZERO);
        assert_eq!(t.len(), 0);
        assert!(t.is_empty());
    }

    #[test]
    fn root_changes_when_slot_added() {
        let mut t = StorageTrie::new();
        let r0 = t.root();
        t.set(U256::from(1u64), U256::from(100u64));
        let r1 = t.root();
        assert_ne!(r0, r1);
        t.set(U256::from(2u64), U256::from(200u64));
        let r2 = t.root();
        assert_ne!(r1, r2);
    }

    #[test]
    fn root_independent_of_insertion_order() {
        let mut a = StorageTrie::new();
        a.set(U256::from(1u64), U256::from(100u64));
        a.set(U256::from(2u64), U256::from(200u64));

        let mut b = StorageTrie::new();
        b.set(U256::from(2u64), U256::from(200u64));
        b.set(U256::from(1u64), U256::from(100u64));

        assert_eq!(a.root(), b.root());
    }

    #[test]
    fn zero_slot_is_equivalent_to_absent() {
        let mut a = StorageTrie::new();
        a.set(U256::from(1u64), U256::ZERO);

        let b = StorageTrie::new();

        assert_eq!(a.root(), b.root());
    }

    #[test]
    fn max_u256_slot_value() {
        let mut t = StorageTrie::new();
        t.set(U256::MAX, U256::MAX);
        assert_eq!(t.get(U256::MAX), U256::MAX);
    }

    #[test]
    fn storage_value_roundtrip() {
        for v in [U256::ZERO, U256::from(1u64), U256::MAX] {
            let bytes = encode_storage_value(v);
            assert_eq!(decode_storage_value(&bytes).unwrap(), v);
        }
    }
}
