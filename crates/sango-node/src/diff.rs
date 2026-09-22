//! Diff d'état entre deux snapshots.
//!
//! Utilisé par [`crate::Node`] après chaque bloc : on compare l'état
//! `before` (avant application) et `after` (après) pour identifier
//! précisément les entrées à persister.

use std::collections::BTreeMap;

use sango_primitives::Hash32;
use sango_state::NativeState;

/// Ensemble des modifications d'état.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StateDiff {
    /// Entrées présentes dans `after` mais pas dans `before`.
    pub inserts: Vec<(Hash32, Vec<u8>)>,
    /// Entrées présentes dans les deux mais avec une valeur différente.
    pub updates: Vec<(Hash32, Vec<u8>)>,
    /// Entrées présentes dans `before` mais pas dans `after`.
    pub deletes: Vec<Hash32>,
}

impl StateDiff {
    /// Vrai si aucune modification.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inserts.is_empty() && self.updates.is_empty() && self.deletes.is_empty()
    }

    /// Nombre total de modifications.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inserts.len() + self.updates.len() + self.deletes.len()
    }
}

/// Calcule le diff entre deux états.
///
/// Les entrées sont traitées dans l'ordre byte-lex croissant de leur
/// `key_hash`, ce qui rend le diff déterministe.
#[must_use]
pub fn diff_state(before: &NativeState, after: &NativeState) -> StateDiff {
    let before_map: BTreeMap<Hash32, Vec<u8>> = before
        .iter_entries()
        .map(|(k, v)| (*k, v.clone()))
        .collect();
    let after_map: BTreeMap<Hash32, Vec<u8>> =
        after.iter_entries().map(|(k, v)| (*k, v.clone())).collect();

    let mut inserts = Vec::new();
    let mut updates = Vec::new();
    let mut deletes = Vec::new();

    for (k, v) in &after_map {
        match before_map.get(k) {
            None => inserts.push((*k, v.clone())),
            Some(old) if old != v => updates.push((*k, v.clone())),
            Some(_) => {}
        }
    }

    for k in before_map.keys() {
        if !after_map.contains_key(k) {
            deletes.push(*k);
        }
    }

    StateDiff {
        inserts,
        updates,
        deletes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sango_crypto::NativeKeypair;
    use sango_primitives::{Amount, NativeAddress};
    use sango_state::Namespace;
    use sango_types::NativeAccount;

    fn addr(b: u8) -> NativeAddress {
        NativeAddress::from_bytes([b; 20])
    }

    #[test]
    fn empty_diff_when_identical() {
        let a = NativeState::new();
        let b = NativeState::new();
        assert!(diff_state(&a, &b).is_empty());
    }

    #[test]
    fn detects_insert() {
        let a = NativeState::new();
        let mut b = NativeState::new();
        b.credit(addr(0xaa), Amount::from_base_units(100)).unwrap();

        let d = diff_state(&a, &b);
        assert_eq!(d.inserts.len(), 1);
        assert!(d.updates.is_empty());
        assert!(d.deletes.is_empty());
    }

    #[test]
    fn detects_update() {
        let mut a = NativeState::new();
        a.credit(addr(0xaa), Amount::from_base_units(100)).unwrap();
        let mut b = a.clone();
        b.credit(addr(0xaa), Amount::from_base_units(50)).unwrap();

        let d = diff_state(&a, &b);
        assert!(d.inserts.is_empty());
        assert_eq!(d.updates.len(), 1);
        assert!(d.deletes.is_empty());
    }

    #[test]
    fn detects_delete() {
        let mut a = NativeState::new();
        a.credit(addr(0xaa), Amount::from_base_units(100)).unwrap();
        let b = NativeState::new();

        let d = diff_state(&a, &b);
        assert!(d.inserts.is_empty());
        assert!(d.updates.is_empty());
        assert_eq!(d.deletes.len(), 1);
    }

    #[test]
    fn detects_mixed_changes() {
        let mut a = NativeState::new();
        a.credit(addr(0xaa), Amount::from_base_units(100)).unwrap();
        a.credit(addr(0xbb), Amount::from_base_units(200)).unwrap();
        a.credit(addr(0xcc), Amount::from_base_units(300)).unwrap();

        let mut b = NativeState::new();
        b.credit(addr(0xaa), Amount::from_base_units(100)).unwrap(); // unchanged
        b.credit(addr(0xbb), Amount::from_base_units(999)).unwrap(); // updated
        b.credit(addr(0xdd), Amount::from_base_units(400)).unwrap(); // inserted
                                                                     // 0xcc removed

        let d = diff_state(&a, &b);
        assert_eq!(d.inserts.len(), 1);
        assert_eq!(d.updates.len(), 1);
        assert_eq!(d.deletes.len(), 1);
        assert_eq!(d.len(), 3);
    }

    #[test]
    fn metadata_changes_are_detected() {
        let a = NativeState::new();
        let mut b = NativeState::new();
        b.add_burned(Amount::from_base_units(42)).unwrap();
        b.add_gas_used(21_000).unwrap();

        let d = diff_state(&a, &b);
        assert_eq!(d.inserts.len(), 2); // total_burned + total_gas_used
    }

    #[test]
    fn is_order_independent_on_keys() {
        // Deux états modifiés dans des ordres différents donnent un diff
        // dont les inserts/updates/deletes sont triés par key_hash.
        let mut a = NativeState::new();
        a.credit(addr(0xaa), Amount::from_base_units(1)).unwrap();
        let mut b = a.clone();
        b.credit(addr(0xbb), Amount::from_base_units(2)).unwrap();
        b.credit(addr(0xcc), Amount::from_base_units(3)).unwrap();

        let d = diff_state(&a, &b);
        // Les key_hash sont triés par ordre byte-lex croissant.
        let mut sorted = d.inserts.clone();
        sorted.sort_by_key(|x| x.0);
        assert_eq!(d.inserts, sorted);
    }

    // Marqueur anti-warning pour certains imports utilisés uniquement
    // dans des contextes spécifiques.
    #[allow(dead_code)]
    fn _marker() {
        let _ = Namespace::NativeAccount;
        let _ = NativeAccount::default();
        let _ = NativeKeypair::from_seed([0; 32]);
    }
}
