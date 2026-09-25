//! Diff d'état entre deux snapshots.
//!
//! Utilisé par [`crate::Node`] après chaque bloc : on compare l'état
//! `before` (avant application) et `after` (après) pour identifier
//! précisément les entrées à persister.

use std::collections::BTreeMap;

use sango_evm::EvmState;
use sango_primitives::{EvmAddress, Hash32};
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

// --- Diff EVM ---------------------------------------------------------------

/// Ensemble des modifications d'état EVM.
///
/// Les entrées sont triées par ordre byte-lex croissant (via `BTreeMap`),
/// ce qui rend le diff déterministe et reproductible.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvmDiff {
    /// Comptes EVM : `(keccak_addr, RLP account)`.
    pub account_inserts: Vec<(Hash32, Vec<u8>)>,
    /// Comptes EVM modifiés.
    pub account_updates: Vec<(Hash32, Vec<u8>)>,
    /// Comptes EVM supprimés (`keccak_addr`).
    pub account_deletes: Vec<Hash32>,
    /// Storage EVM : `(evm_addr, slot_hash, RLP value)`.
    pub storage_inserts: Vec<(EvmAddress, Hash32, Vec<u8>)>,
    /// Storage EVM modifié.
    pub storage_updates: Vec<(EvmAddress, Hash32, Vec<u8>)>,
    /// Storage EVM supprimé : `(evm_addr, slot_hash)`.
    pub storage_deletes: Vec<(EvmAddress, Hash32)>,
    /// Bytecode EVM : `(code_hash, bytecode)`. **Pas de suppression**
    /// possible : le code est immuable, indexé par son hash.
    pub code_inserts: Vec<(Hash32, Vec<u8>)>,
}

impl EvmDiff {
    /// Vrai si aucune modification.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.account_inserts.is_empty()
            && self.account_updates.is_empty()
            && self.account_deletes.is_empty()
            && self.storage_inserts.is_empty()
            && self.storage_updates.is_empty()
            && self.storage_deletes.is_empty()
            && self.code_inserts.is_empty()
    }

    /// Nombre total de modifications.
    #[must_use]
    pub fn len(&self) -> usize {
        self.account_inserts.len()
            + self.account_updates.len()
            + self.account_deletes.len()
            + self.storage_inserts.len()
            + self.storage_updates.len()
            + self.storage_deletes.len()
            + self.code_inserts.len()
    }
}

/// Calcule le diff entre deux états EVM.
///
/// ## Déterminisme
///
/// L'itération sur `EvmState` est triée par clé (`BTreeMap` interne), donc
/// le diff est **strictement déterministe** : deux nœuds qui appliquent le
/// même bloc produisent le même `EvmDiff`.
#[must_use]
pub fn diff_evm(before: &EvmState, after: &EvmState) -> EvmDiff {
    // --- Comptes ---
    let before_acc: BTreeMap<Hash32, Vec<u8>> = before
        .iter_account_entries()
        .map(|(k, v)| (*k, v.clone()))
        .collect();
    let after_acc: BTreeMap<Hash32, Vec<u8>> = after
        .iter_account_entries()
        .map(|(k, v)| (*k, v.clone()))
        .collect();

    let mut account_inserts = Vec::new();
    let mut account_updates = Vec::new();
    let mut account_deletes = Vec::new();

    for (k, v) in &after_acc {
        match before_acc.get(k) {
            None => account_inserts.push((*k, v.clone())),
            Some(old) if old != v => account_updates.push((*k, v.clone())),
            Some(_) => {}
        }
    }
    for k in before_acc.keys() {
        if !after_acc.contains_key(k) {
            account_deletes.push(*k);
        }
    }

    // --- Storage ---
    let before_sto: BTreeMap<(EvmAddress, Hash32), Vec<u8>> = before
        .iter_storage_entries()
        .into_iter()
        .map(|(a, s, v)| ((a, s), v))
        .collect();
    let after_sto: BTreeMap<(EvmAddress, Hash32), Vec<u8>> = after
        .iter_storage_entries()
        .into_iter()
        .map(|(a, s, v)| ((a, s), v))
        .collect();

    let mut storage_inserts = Vec::new();
    let mut storage_updates = Vec::new();
    let mut storage_deletes = Vec::new();

    for ((addr, slot), v) in &after_sto {
        match before_sto.get(&(*addr, *slot)) {
            None => storage_inserts.push((*addr, *slot, v.clone())),
            Some(old) if old != v => storage_updates.push((*addr, *slot, v.clone())),
            Some(_) => {}
        }
    }
    for (addr, slot) in before_sto.keys() {
        if !after_sto.contains_key(&(*addr, *slot)) {
            storage_deletes.push((*addr, *slot));
        }
    }

    // --- Code ---
    let before_code: BTreeMap<Hash32, Vec<u8>> = before
        .iter_code_entries()
        .map(|(k, v)| (*k, v.clone()))
        .collect();
    let after_code: BTreeMap<Hash32, Vec<u8>> = after
        .iter_code_entries()
        .map(|(k, v)| (*k, v.clone()))
        .collect();

    let mut code_inserts = Vec::new();
    for (k, v) in &after_code {
        if !before_code.contains_key(k) {
            code_inserts.push((*k, v.clone()));
        }
    }

    EvmDiff {
        account_inserts,
        account_updates,
        account_deletes,
        storage_inserts,
        storage_updates,
        storage_deletes,
        code_inserts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sango_primitives::{Amount, NativeAddress};

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

    // --- Diff EVM ---------------------------------------------------------

    use sango_primitives::{EvmAddress, U256};
    use sango_types::EvmAccount;

    fn evm_addr(b: u8) -> EvmAddress {
        EvmAddress::from_bytes([b; 20])
    }

    fn evm_account(nonce: u64, balance: u64) -> EvmAccount {
        let mut a = EvmAccount::empty();
        a.nonce = nonce;
        a.balance = U256::from(balance);
        a
    }

    #[test]
    fn evm_empty_diff_when_identical() {
        let a = EvmState::new();
        let b = EvmState::new();
        assert!(diff_evm(&a, &b).is_empty());
    }

    #[test]
    fn evm_detects_account_insert() {
        let a = EvmState::new();
        let mut b = EvmState::new();
        b.set_account(evm_addr(0xaa), evm_account(0, 0));
        let d = diff_evm(&a, &b);
        assert_eq!(d.account_inserts.len(), 1);
        assert!(d.account_updates.is_empty());
        assert!(d.account_deletes.is_empty());
    }

    #[test]
    fn evm_detects_account_update() {
        let mut a = EvmState::new();
        a.set_account(evm_addr(0xaa), evm_account(1, 100));
        let mut b = a.clone();
        b.set_account(evm_addr(0xaa), evm_account(2, 200));
        let d = diff_evm(&a, &b);
        assert!(d.account_inserts.is_empty());
        assert_eq!(d.account_updates.len(), 1);
    }

    #[test]
    fn evm_detects_account_delete() {
        let mut a = EvmState::new();
        a.set_account(evm_addr(0xaa), evm_account(1, 100));
        let b = EvmState::new();
        let d = diff_evm(&a, &b);
        assert!(d.account_inserts.is_empty());
        assert_eq!(d.account_deletes.len(), 1);
    }

    #[test]
    fn evm_detects_storage_changes() {
        let mut a = EvmState::new();
        a.set_storage(evm_addr(0xaa), U256::from(1u64), U256::from(100u64));
        a.set_storage(evm_addr(0xaa), U256::from(2u64), U256::from(200u64));

        let mut b = a.clone();
        // Update slot 1, delete slot 2, add slot 3.
        b.set_storage(evm_addr(0xaa), U256::from(1u64), U256::from(999u64));
        b.set_storage(evm_addr(0xaa), U256::from(2u64), U256::ZERO);
        b.set_storage(evm_addr(0xaa), U256::from(3u64), U256::from(300u64));

        let d = diff_evm(&a, &b);
        assert_eq!(d.storage_updates.len(), 1);
        assert_eq!(d.storage_deletes.len(), 1);
        assert_eq!(d.storage_inserts.len(), 1);
    }

    #[test]
    fn evm_detects_code_insert() {
        let a = EvmState::new();
        let mut b = EvmState::new();
        let code = vec![0x60, 0x01];
        let ch = sango_crypto::keccak256(&code);
        b.put_code(ch, code).unwrap();
        let d = diff_evm(&a, &b);
        assert_eq!(d.code_inserts.len(), 1);
        assert_eq!(d.code_inserts[0].0, ch);
    }

    #[test]
    fn evm_code_is_monotonic() {
        // Un code inséré dans `a` et toujours présent dans `b` ne
        // produit aucune modification (code immuable).
        let mut a = EvmState::new();
        let code = vec![0x60, 0x01];
        let ch = sango_crypto::keccak256(&code);
        a.put_code(ch, code.clone()).unwrap();
        let b = a.clone();
        let d = diff_evm(&a, &b);
        assert!(d.code_inserts.is_empty());
        assert!(d.is_empty());
    }

    #[test]
    fn evm_diff_is_deterministic() {
        let mut a = EvmState::new();
        a.set_account(evm_addr(0x01), evm_account(1, 100));
        a.set_storage(evm_addr(0x01), U256::from(1u64), U256::from(1u64));
        let mut b = a.clone();
        b.set_account(evm_addr(0x02), evm_account(2, 200));
        b.set_storage(evm_addr(0x02), U256::from(2u64), U256::from(2u64));

        let d1 = diff_evm(&a, &b);
        let d2 = diff_evm(&a, &b);
        assert_eq!(d1, d2);
    }
}
