//! État EVM (accounts + storage tries + code).
//!
//! ## Architecture
//!
//! ```text
//!             EvmState
//!                │
//!    ┌───────────┼──────────────┐
//!    ▼           ▼              ▼
//! Account MPT   Storage MPTs   Code DB
//! keccak(addr)  addr →         code_hash →
//!  → RLP         (slot → RLP)   bytecode
//! ```
//!
//! ## Invariant code
//!
//! `Keccak256(bytecode) == code_hash` **toujours**. `put_code` vérifie cet
//! invariant et rejette toute insertion incohérente.
//!
//! ## Le code NE FAIT PAS partie du state_root
//!
//! Le `state_root` est le MPT des comptes. Les comptes committent au code
//! via `code_hash` (32 bytes) dans leur propre feuille. Le bytecode lui-même
//! est stocké hors MPT, indexé par son hash.

use std::collections::BTreeMap;

use sango_crypto::keccak256;
use sango_primitives::{EvmAddress, Hash32, U256};
use sango_types::EvmAccount;

use crate::account::{decode_account, empty_code_hash, encode_account};
use crate::error::EvmError;
use crate::storage::StorageTrie;

/// État EVM complet (accounts + storage + code).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvmState {
    /// `Keccak256(evm_address)` → `RLP(account)`.
    accounts: BTreeMap<Hash32, Vec<u8>>,
    /// `evm_address` → storage trie.
    storages: BTreeMap<EvmAddress, StorageTrie>,
    /// `code_hash` → bytecode brut.
    code: BTreeMap<Hash32, Vec<u8>>,
}

impl EvmState {
    /// État vide.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Nombre de comptes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.accounts.len()
    }

    /// Vrai si aucun compte n'est présent.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }

    // --- Comptes -----------------------------------------------------------

    /// Vrai si un compte existe.
    #[must_use]
    pub fn account_exists(&self, addr: &EvmAddress) -> bool {
        let key = keccak256(addr.as_bytes());
        self.accounts.contains_key(&key)
    }

    /// Lit un compte. Retourne `None` si absent.
    #[must_use]
    pub fn get_account(&self, addr: &EvmAddress) -> Option<EvmAccount> {
        let key = keccak256(addr.as_bytes());
        self.accounts
            .get(&key)
            .and_then(|raw| decode_account(raw).ok())
    }

    /// Écrit un compte. Remplace s'il existe.
    pub fn set_account(&mut self, addr: EvmAddress, acc: EvmAccount) {
        let key = keccak256(addr.as_bytes());
        self.accounts.insert(key, encode_account(&acc));
    }

    /// Supprime un compte et son storage associé.
    pub fn remove_account(&mut self, addr: &EvmAddress) -> Option<EvmAccount> {
        let key = keccak256(addr.as_bytes());
        let removed = self
            .accounts
            .remove(&key)
            .and_then(|raw| decode_account(&raw).ok());
        self.storages.remove(addr);
        removed
    }

    // --- Storage -----------------------------------------------------------

    /// Lit la valeur d'un slot de storage. `U256::ZERO` si absent.
    #[must_use]
    pub fn get_storage(&self, addr: &EvmAddress, slot: U256) -> U256 {
        match self.storages.get(addr) {
            Some(t) => t.get(slot),
            None => U256::ZERO,
        }
    }

    /// Écrit un slot de storage.
    ///
    /// Met à jour automatiquement le `storage_root` du compte propriétaire.
    /// Crée un compte par défaut si l'adresse n'existe pas.
    pub fn set_storage(&mut self, addr: EvmAddress, slot: U256, value: U256) {
        let trie = self.storages.entry(addr).or_default();
        trie.set(slot, value);
        if trie.is_empty() {
            self.storages.remove(&addr);
        }

        let new_root = self.compute_storage_root(&addr);
        let addr_key = keccak256(addr.as_bytes());
        let mut acc = match self.accounts.get(&addr_key) {
            Some(raw) => decode_account(raw).unwrap_or_else(|_| EvmAccount::empty()),
            None => EvmAccount::empty(),
        };
        acc.storage_root = new_root;
        self.accounts.insert(addr_key, encode_account(&acc));
    }

    /// Racine MPT du storage trie d'un compte.
    #[must_use]
    pub fn storage_root(&self, addr: &EvmAddress) -> Hash32 {
        self.compute_storage_root(addr)
    }

    fn compute_storage_root(&self, addr: &EvmAddress) -> Hash32 {
        match self.storages.get(addr) {
            Some(t) => t.root(),
            None => sango_mpt::empty_root(),
        }
    }

    // --- Code --------------------------------------------------------------

    /// Insère un bytecode, en vérifiant `Keccak256(bytecode) == code_hash`.
    ///
    /// # Erreurs
    ///
    /// [`EvmError::CodeHashMismatch`] si le hash recalculé diffère de la
    /// clé fournie.
    pub fn put_code(&mut self, code_hash: Hash32, bytecode: Vec<u8>) -> Result<(), EvmError> {
        let computed = keccak256(&bytecode);
        if computed != code_hash {
            return Err(EvmError::CodeHashMismatch {
                expected: code_hash,
                computed,
            });
        }
        self.code.insert(code_hash, bytecode);
        Ok(())
    }

    /// Lit un bytecode par hash. **Vérifie l'invariant** au retour.
    ///
    /// # Erreurs
    ///
    /// - [`EvmError::CodeNotFound`] si absent ;
    /// - [`EvmError::CodeHashMismatch`] si le bytecode stocké a été corrompu.
    pub fn get_code(&self, code_hash: &Hash32) -> Result<&[u8], EvmError> {
        let bytes = self.code.get(code_hash).ok_or(EvmError::CodeNotFound {
            code_hash: *code_hash,
        })?;
        let computed = keccak256(bytes);
        if computed != *code_hash {
            return Err(EvmError::CodeHashMismatch {
                expected: *code_hash,
                computed,
            });
        }
        Ok(bytes.as_slice())
    }

    /// Vrai si un bytecode est présent pour ce hash.
    #[must_use]
    pub fn has_code(&self, code_hash: &Hash32) -> bool {
        self.code.contains_key(code_hash)
    }

    /// Itère sur les entrées `(code_hash, bytecode)`.
    pub fn iter_code_entries(&self) -> impl Iterator<Item = (&Hash32, &Vec<u8>)> {
        self.code.iter()
    }

    /// Restaure une entrée code brute (chargement RocksDB).
    ///
    /// **Vérifie l'invariant** `Keccak256(value) == key_hash`.
    pub fn restore_code_entry(
        &mut self,
        code_hash: Hash32,
        bytecode: Vec<u8>,
    ) -> Result<(), EvmError> {
        let computed = keccak256(&bytecode);
        if computed != code_hash {
            return Err(EvmError::CodeHashMismatch {
                expected: code_hash,
                computed,
            });
        }
        self.code.insert(code_hash, bytecode);
        Ok(())
    }

    // --- Roots -------------------------------------------------------------

    /// Racine MPT du state trie (accounts).
    #[must_use]
    pub fn state_root(&self) -> Hash32 {
        let entries: Vec<(Vec<u8>, Vec<u8>)> = self
            .accounts
            .iter()
            .map(|(k, v)| (k.as_bytes().to_vec(), v.clone()))
            .collect();
        sango_mpt::mpt_root(&entries)
    }

    // --- Itération ---------------------------------------------------------

    /// Itère sur les entrées `(keccak_addr, RLP account)`.
    pub fn iter_account_entries(&self) -> impl Iterator<Item = (&Hash32, &Vec<u8>)> {
        self.accounts.iter()
    }

    /// Itère sur les entrées `(addr, slot_hash, RLP value)` de tous les
    /// storage tries.
    pub fn iter_storage_entries(&self) -> Vec<(EvmAddress, Hash32, Vec<u8>)> {
        let mut out = Vec::new();
        for (addr, trie) in &self.storages {
            for (slot_hash, value) in trie.iter_entries() {
                out.push((*addr, *slot_hash, value.clone()));
            }
        }
        out
    }

    /// Restaure une entrée account brute.
    pub fn restore_account_entry(&mut self, addr_hash: Hash32, value: Vec<u8>) {
        self.accounts.insert(addr_hash, value);
    }

    /// Restaure une entrée storage brute.
    pub fn restore_storage_entry(&mut self, addr: EvmAddress, slot_hash: Hash32, value: Vec<u8>) {
        self.storages
            .entry(addr)
            .or_default()
            .restore_entry(slot_hash, value);
    }
}

/// Vrai si le compte est "vide" au sens Ethereum.
#[must_use]
pub fn is_eoa_empty(acc: &EvmAccount) -> bool {
    acc.nonce == 0 && acc.balance == U256::ZERO && acc.code_hash == empty_code_hash()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> EvmAddress {
        EvmAddress::from_bytes([b; 20])
    }

    fn make_account(nonce: u64, balance: u64) -> EvmAccount {
        EvmAccount {
            nonce,
            balance: U256::from(balance),
            storage_root: sango_mpt::empty_root(),
            code_hash: empty_code_hash(),
        }
    }

    // --- Comptes (inchangés) ----------------------------------------------

    #[test]
    fn empty_state_root_matches_mpt_empty() {
        let s = EvmState::new();
        assert_eq!(s.state_root(), sango_mpt::empty_root());
    }

    #[test]
    fn empty_state_is_empty() {
        let s = EvmState::new();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn account_roundtrip() {
        let mut s = EvmState::new();
        let a = addr(0xaa);
        let acc = make_account(1, 1000);
        s.set_account(a, acc);
        assert_eq!(s.get_account(&a), Some(acc));
        assert!(s.account_exists(&a));
    }

    #[test]
    fn state_root_changes_with_account() {
        let mut s = EvmState::new();
        let r0 = s.state_root();
        s.set_account(addr(0xaa), make_account(0, 0));
        let r1 = s.state_root();
        assert_ne!(r0, r1);
    }

    #[test]
    fn remove_account_clears_it() {
        let mut s = EvmState::new();
        let a = addr(0xaa);
        s.set_account(a, make_account(1, 100));
        assert!(s.account_exists(&a));
        let removed = s.remove_account(&a);
        assert!(removed.is_some());
        assert!(!s.account_exists(&a));
        assert_eq!(s.state_root(), sango_mpt::empty_root());
    }

    #[test]
    fn state_root_is_order_independent() {
        let mut a = EvmState::new();
        a.set_account(addr(0x01), make_account(1, 100));
        a.set_account(addr(0x02), make_account(2, 200));

        let mut b = EvmState::new();
        b.set_account(addr(0x02), make_account(2, 200));
        b.set_account(addr(0x01), make_account(1, 100));

        assert_eq!(a.state_root(), b.state_root());
    }

    // --- Storage (inchangés) ----------------------------------------------

    #[test]
    fn storage_absent_is_zero() {
        let s = EvmState::new();
        assert_eq!(s.get_storage(&addr(0xaa), U256::from(1u64)), U256::ZERO);
    }

    #[test]
    fn set_storage_creates_account_if_missing() {
        let mut s = EvmState::new();
        let a = addr(0xaa);
        assert!(!s.account_exists(&a));
        s.set_storage(a, U256::from(1u64), U256::from(42u64));
        assert!(s.account_exists(&a));
        assert_eq!(s.get_storage(&a, U256::from(1u64)), U256::from(42u64));
    }

    #[test]
    fn set_storage_updates_storage_root_in_account() {
        let mut s = EvmState::new();
        let a = addr(0xaa);
        s.set_account(a, make_account(1, 0));
        let root_before = s.get_account(&a).unwrap().storage_root;

        s.set_storage(a, U256::from(1u64), U256::from(42u64));

        let root_after = s.get_account(&a).unwrap().storage_root;
        assert_ne!(root_before, root_after);
        assert_eq!(root_after, s.storage_root(&a));
    }

    #[test]
    fn storage_removal_restores_empty_root() {
        let mut s = EvmState::new();
        let a = addr(0xaa);
        s.set_storage(a, U256::from(1u64), U256::from(42u64));
        s.set_storage(a, U256::from(1u64), U256::ZERO);

        assert_eq!(s.get_storage(&a, U256::from(1u64)), U256::ZERO);
        assert_eq!(s.storage_root(&a), sango_mpt::empty_root());
    }

    #[test]
    fn storage_two_accounts_independent() {
        let mut s = EvmState::new();
        let a = addr(0xaa);
        let b = addr(0xbb);
        s.set_storage(a, U256::from(1u64), U256::from(100u64));
        s.set_storage(b, U256::from(1u64), U256::from(200u64));

        assert_eq!(s.get_storage(&a, U256::from(1u64)), U256::from(100u64));
        assert_eq!(s.get_storage(&b, U256::from(1u64)), U256::from(200u64));
        assert_ne!(s.storage_root(&a), s.storage_root(&b));
    }

    #[test]
    fn remove_account_removes_storage() {
        let mut s = EvmState::new();
        let a = addr(0xaa);
        s.set_storage(a, U256::from(1u64), U256::from(42u64));
        s.remove_account(&a);
        assert_eq!(s.get_storage(&a, U256::from(1u64)), U256::ZERO);
        assert_eq!(s.storage_root(&a), sango_mpt::empty_root());
    }

    #[test]
    fn state_root_changes_with_storage() {
        let mut s = EvmState::new();
        let a = addr(0xaa);
        s.set_account(a, make_account(1, 0));
        let r0 = s.state_root();
        s.set_storage(a, U256::from(1u64), U256::from(42u64));
        let r1 = s.state_root();
        assert_ne!(r0, r1);
    }

    // --- Code (nouveaux) --------------------------------------------------

    #[test]
    fn put_get_code_roundtrip() {
        let mut s = EvmState::new();
        let bytecode = vec![0x60, 0x01, 0x60, 0x02, 0x01];
        let code_hash = keccak256(&bytecode);
        s.put_code(code_hash, bytecode.clone()).unwrap();
        assert_eq!(s.get_code(&code_hash).unwrap(), bytecode.as_slice());
        assert!(s.has_code(&code_hash));
    }

    #[test]
    fn put_code_rejects_hash_mismatch() {
        let mut s = EvmState::new();
        let bytecode = vec![0x60, 0x01];
        let wrong_hash = Hash32::from_bytes([0xff; 32]);
        let err = s.put_code(wrong_hash, bytecode).unwrap_err();
        assert!(matches!(err, EvmError::CodeHashMismatch { .. }));
    }

    #[test]
    fn get_code_missing_returns_error() {
        let s = EvmState::new();
        let err = s.get_code(&Hash32::from_bytes([0x11; 32])).unwrap_err();
        assert!(matches!(err, EvmError::CodeNotFound { .. }));
    }

    #[test]
    fn code_does_not_change_state_root() {
        let mut s = EvmState::new();
        s.set_account(addr(0xaa), make_account(1, 100));
        let root_before = s.state_root();

        let bytecode = vec![0x60, 0x01];
        let code_hash = keccak256(&bytecode);
        s.put_code(code_hash, bytecode).unwrap();

        // Le code n'entre pas dans le state_root. Les comptes y committent
        // via `code_hash`.
        assert_eq!(s.state_root(), root_before);
    }

    #[test]
    fn restore_code_entry_verifies_invariant() {
        let mut s = EvmState::new();
        let bytecode = vec![0xaa, 0xbb];
        let code_hash = keccak256(&bytecode);
        s.restore_code_entry(code_hash, bytecode.clone()).unwrap();
        assert_eq!(s.get_code(&code_hash).unwrap(), bytecode.as_slice());

        let err = s
            .restore_code_entry(Hash32::from_bytes([0x00; 32]), bytecode)
            .unwrap_err();
        assert!(matches!(err, EvmError::CodeHashMismatch { .. }));
    }

    // --- Iter / restore ---------------------------------------------------

    #[test]
    fn iter_account_entries_returns_all() {
        let mut s = EvmState::new();
        s.set_account(addr(0x01), make_account(1, 0));
        s.set_account(addr(0x02), make_account(2, 0));
        assert_eq!(s.iter_account_entries().count(), 2);
    }

    #[test]
    fn iter_storage_entries_returns_all() {
        let mut s = EvmState::new();
        let a = addr(0xaa);
        s.set_storage(a, U256::from(1u64), U256::from(100u64));
        s.set_storage(a, U256::from(2u64), U256::from(200u64));
        let entries = s.iter_storage_entries();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn iter_code_entries_returns_all() {
        let mut s = EvmState::new();
        let b1 = vec![0x01];
        let b2 = vec![0x02, 0x03];
        s.put_code(keccak256(&b1), b1).unwrap();
        s.put_code(keccak256(&b2), b2).unwrap();
        assert_eq!(s.iter_code_entries().count(), 2);
    }

    #[test]
    fn restore_preserves_state_root() {
        let mut original = EvmState::new();
        original.set_account(addr(0xaa), make_account(1, 100));
        original.set_storage(addr(0xaa), U256::from(1u64), U256::from(42u64));

        let root = original.state_root();
        let account_entries: Vec<_> = original
            .iter_account_entries()
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        let storage_entries = original.iter_storage_entries();

        let mut restored = EvmState::new();
        for (k, v) in account_entries {
            restored.restore_account_entry(k, v);
        }
        for (addr, slot_hash, value) in storage_entries {
            restored.restore_storage_entry(addr, slot_hash, value);
        }

        assert_eq!(restored.state_root(), root);
    }

    // --- is_eoa_empty -----------------------------------------------------

    #[test]
    fn empty_account_is_eoa_empty() {
        let acc = EvmAccount::empty();
        assert!(is_eoa_empty(&acc));
    }

    #[test]
    fn non_empty_account_is_not_eoa_empty() {
        let acc = make_account(1, 0);
        assert!(!is_eoa_empty(&acc));
    }
}
