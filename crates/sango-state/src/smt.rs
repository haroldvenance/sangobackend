//! Sparse Merkle Tree binaire 256 niveaux, Keccak-256.
//!
//! Structure **FROZEN V1** :
//!
//! - hauteur : 256 décisions de branchement + 1 niveau de feuilles ;
//! - clé   : `Hash32` (32 bytes) ;
//! - chemin : bit 255 → bit 0 (MSB du byte 0 en premier) ;
//! - hash de feuille :
//!   `Keccak256("SANGO/STATE/LEAF/V1" || key_hash || u32_be(value_len) || value)`
//! - hash de nœud :
//!   `Keccak256("SANGO/STATE/NODE/V1" || left_hash || right_hash)`
//! - feuille vide :
//!   `EMPTY[0] = Keccak256("SANGO/STATE/EMPTY/LEAF/V1")`
//! - remontée :
//!   `EMPTY[i+1] = Keccak256("SANGO/STATE/NODE/V1" || EMPTY[i] || EMPTY[i])`
//! - racine d'un état vide : `EMPTY[256]`.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use sango_crypto::{domain, hash_domain_parts, keccak256};
use sango_primitives::Hash32;

/// Hauteur maximale : 256 décisions de branchement.
pub const TREE_HEIGHT: usize = 256;

/// Table des hachages de sous-arbres vides, indexée par hauteur.
///
/// `EMPTY[0]` : feuille vide.
/// `EMPTY[256]` : racine d'un arbre entièrement vide.
static EMPTY: LazyLock<[Hash32; TREE_HEIGHT + 1]> = LazyLock::new(|| {
    let mut empty = [Hash32::ZERO; TREE_HEIGHT + 1];
    empty[0] = keccak256(domain::NATIVE_STATE_EMPTY_LEAF_V1);
    for i in 1..=TREE_HEIGHT {
        empty[i] = node_hash(empty[i - 1], empty[i - 1]);
    }
    empty
});

/// Racine d'un SMT vide.
#[must_use]
pub fn empty_root() -> Hash32 {
    EMPTY[TREE_HEIGHT]
}

/// Hash d'un nœud interne.
fn node_hash(left: Hash32, right: Hash32) -> Hash32 {
    let parts: &[&[u8]] = &[left.as_bytes(), right.as_bytes()];
    hash_domain_parts(domain::NATIVE_STATE_NODE_V1, parts)
}

/// Hash d'une feuille non vide.
///
/// Le préfixe de longueur est `u32_be` — **uniquement** pour ce hash, le
/// codec Sango général reste LE.
fn leaf_hash(key_hash: &Hash32, value: &[u8]) -> Hash32 {
    let len: u32 = value
        .len()
        .try_into()
        .expect("state value length exceeds u32::MAX");
    let len_be = len.to_be_bytes();
    let parts: &[&[u8]] = &[key_hash.as_bytes(), &len_be, value];
    hash_domain_parts(domain::NATIVE_STATE_LEAF_V1, parts)
}

/// Lit le bit à `bit_index` (0 = LSB du byte 31, 255 = MSB du byte 0).
#[inline]
fn bit_at(h: &Hash32, bit_index: u8) -> u8 {
    let byte_index = 31 - (bit_index / 8) as usize;
    let bit_in_byte = bit_index % 8;
    (h.as_bytes()[byte_index] >> bit_in_byte) & 1
}

/// Sparse Merkle Tree binaire 256 niveaux.
#[derive(Debug, Clone, Default)]
pub struct SparseMerkleTree {
    /// Entrées indexées par `key_hash`. `BTreeMap` garantit l'ordre
    /// byte-lex, équivalent à l'ordre bit-lex MSB-first.
    entries: BTreeMap<Hash32, Vec<u8>>,
}

impl SparseMerkleTree {
    /// Crée un arbre vide.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Nombre d'entrées.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Vrai si l'arbre est vide.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Insère ou remplace une entrée.
    pub fn insert(&mut self, key_hash: Hash32, value: Vec<u8>) {
        self.entries.insert(key_hash, value);
    }

    /// Lit une entrée.
    #[must_use]
    pub fn get(&self, key_hash: &Hash32) -> Option<&Vec<u8>> {
        self.entries.get(key_hash)
    }

    /// Supprime une entrée.
    pub fn remove(&mut self, key_hash: &Hash32) -> Option<Vec<u8>> {
        self.entries.remove(key_hash)
    }

    /// Racine de l'arbre.
    #[must_use]
    pub fn root(&self) -> Hash32 {
        if self.entries.is_empty() {
            return empty_root();
        }
        let entries: Vec<(&Hash32, &Vec<u8>)> = self.entries.iter().collect();
        subtree_root(&entries, TREE_HEIGHT)
    }
}

fn subtree_root(entries: &[(&Hash32, &Vec<u8>)], height: usize) -> Hash32 {
    if entries.is_empty() {
        return EMPTY[height];
    }
    if height == 0 {
        debug_assert_eq!(
            entries.len(),
            1,
            "leaf level must contain exactly one entry"
        );
        let (kh, v) = entries[0];
        return leaf_hash(kh, v);
    }
    let bit_index = (height - 1) as u8;
    let split = entries.partition_point(|e| bit_at(e.0, bit_index) == 0);
    let left_hash = subtree_root(&entries[..split], height - 1);
    let right_hash = subtree_root(&entries[split..], height - 1);
    node_hash(left_hash, right_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kh(b: [u8; 32]) -> Hash32 {
        Hash32::from_bytes(b)
    }

    #[test]
    fn empty_root_matches_precomputed() {
        assert_eq!(SparseMerkleTree::new().root(), EMPTY[TREE_HEIGHT]);
    }

    #[test]
    fn empty_root_is_deterministic() {
        let a = SparseMerkleTree::new().root();
        let b = SparseMerkleTree::new().root();
        assert_eq!(a, b);
    }

    #[test]
    fn single_entry_matches_manual_computation() {
        let key = kh([0u8; 32]); // tous les bits à 0 → chemin toujours à gauche
        let value = b"hello".to_vec();

        let mut tree = SparseMerkleTree::new();
        tree.insert(key, value.clone());

        // Calcul manuel : à chaque niveau, l'entrée est dans le sous-arbre gauche
        // (car tous les bits de `key` sont 0), le droit est EMPTY[h-1].
        let leaf = leaf_hash(&key, &value);
        let mut expected = leaf;
        for h in 1..=TREE_HEIGHT {
            // bit (h-1) de `key` = 0 → entry à gauche
            expected = node_hash(expected, EMPTY[h - 1]);
        }

        assert_eq!(tree.root(), expected);
    }

    #[test]
    fn two_entries_diverge_at_bit_zero() {
        // key1 = 0...0 ; key2 = 0...0 suivie du bit 0 = 1
        let key1 = kh([0u8; 32]);
        let mut key2_bytes = [0u8; 32];
        key2_bytes[31] = 0x01;
        let key2 = kh(key2_bytes);

        let v1 = b"a".to_vec();
        let v2 = b"b".to_vec();

        let mut tree = SparseMerkleTree::new();
        tree.insert(key1, v1.clone());
        tree.insert(key2, v2.clone());

        let leaf1 = leaf_hash(&key1, &v1);
        let leaf2 = leaf_hash(&key2, &v2);

        // Au niveau 1, les deux divergent : key1 à gauche, key2 à droite.
        let h1 = node_hash(leaf1, leaf2);

        // Aux niveaux 2..=256, les deux entrées sont dans le même sous-arbre
        // (bits 1..255 = 0), donc à gauche ; le droit est EMPTY[h-1].
        let mut expected = h1;
        for h in 2..=TREE_HEIGHT {
            expected = node_hash(expected, EMPTY[h - 1]);
        }

        assert_eq!(tree.root(), expected);
    }

    #[test]
    fn order_of_insertion_is_irrelevant() {
        let k1 = kh([0x01; 32]);
        let k2 = kh([0x02; 32]);
        let k3 = kh([0x03; 32]);

        let mut a = SparseMerkleTree::new();
        a.insert(k1, vec![1]);
        a.insert(k2, vec![2]);
        a.insert(k3, vec![3]);

        let mut b = SparseMerkleTree::new();
        b.insert(k3, vec![3]);
        b.insert(k1, vec![1]);
        b.insert(k2, vec![2]);

        assert_eq!(a.root(), b.root());
    }

    #[test]
    fn different_values_give_different_roots() {
        let k = kh([0x42; 32]);
        let mut a = SparseMerkleTree::new();
        a.insert(k, vec![1]);
        let mut b = SparseMerkleTree::new();
        b.insert(k, vec![2]);
        assert_ne!(a.root(), b.root());
    }

    #[test]
    fn different_keys_give_different_roots() {
        let mut a = SparseMerkleTree::new();
        a.insert(kh([0x42; 32]), vec![1]);
        let mut b = SparseMerkleTree::new();
        b.insert(kh([0x43; 32]), vec![1]);
        assert_ne!(a.root(), b.root());
    }

    #[test]
    fn remove_restores_previous_root() {
        let k = kh([0x42; 32]);
        let mut t = SparseMerkleTree::new();
        let empty_root_before = t.root();
        t.insert(k, vec![1]);
        assert_ne!(t.root(), empty_root_before);
        t.remove(&k);
        assert_eq!(t.root(), empty_root_before);
    }

    #[test]
    fn leaf_length_prefix_is_big_endian() {
        // Deux valeurs de longueurs différentes mais même préfixe de bytes :
        // vec![1] (len=1) et vec![1, 0] (len=2) doivent avoir des feuilles
        // différentes, ce qui est garanti par le préfixe u32_be.
        let k = kh([0x42; 32]);
        let mut a = SparseMerkleTree::new();
        a.insert(k, vec![1]);
        let mut b = SparseMerkleTree::new();
        b.insert(k, vec![1, 0]);
        assert_ne!(a.root(), b.root());
    }
}
