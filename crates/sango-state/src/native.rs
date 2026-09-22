//! État natif canonique Sango (`NativeState`).
//!
//! ## Structure FROZEN V1
//!
//! - Chaque entrée possède une clé logique `K = namespace_u8 || identifier`.
//! - `key_hash = Keccak256("SANGO/STATE/KEY/V1" || K)`.
//! - Les `key_hash` sont stockés dans un [`SparseMerkleTree`] binaire 256 niveaux.
//! - Les valeurs sont l'encodage canonique Sango du type concerné.
//!
//! RocksDB ne fait que persister les entrées ; il ne définit **jamais** le
//! consensus.
//!
//! ## Métadonnées globales
//!
//! Le namespace [`Namespace::Metadata`] porte les compteurs cumulés :
//!
//! - [`MetadataKey::TotalBurned`] : cumul des SANGO brûlés ;
//! - [`MetadataKey::TotalGasUsed`] : cumul du gas consommé.
//!
//! Ces valeurs font partie du `native_state_root`.

use sango_codec::{Decode, Encode};
use sango_crypto::{derive_native_address, domain, hash_domain};
use sango_primitives::{Amount, Hash32, NativeAddress, PublicKey};
use sango_types::NativeAccount;

use crate::error::StateError;
use crate::metadata::MetadataKey;
use crate::namespace::Namespace;
use crate::smt::{empty_root, SparseMerkleTree};

/// Calcule le hash canonique d'une clé logique d'état.
#[must_use]
pub fn state_key_hash(namespace: Namespace, identifier: &[u8]) -> Hash32 {
    let mut logical = Vec::with_capacity(1 + identifier.len());
    logical.push(namespace.tag());
    logical.extend_from_slice(identifier);
    hash_domain(domain::NATIVE_STATE_KEY_V1, &logical)
}

/// État natif Sango.
#[derive(Debug, Clone, Default)]
pub struct NativeState {
    smt: SparseMerkleTree,
}

impl NativeState {
    /// Crée un état vide.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Nombre d'entrées d'état.
    #[must_use]
    pub fn len(&self) -> usize {
        self.smt.len()
    }

    /// Vrai si l'état est vide.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.smt.is_empty()
    }

    /// Racine de l'état natif (SMT 256 niveaux, Keccak-256).
    #[must_use]
    pub fn native_state_root(&self) -> Hash32 {
        self.smt.root()
    }

    // --- API bas niveau (par namespace) -------------------------------------

    /// Écrit une entrée brute.
    pub fn put_entry(&mut self, namespace: Namespace, identifier: &[u8], value: Vec<u8>) {
        let kh = state_key_hash(namespace, identifier);
        self.smt.insert(kh, value);
    }

    /// Lit une entrée brute.
    #[must_use]
    pub fn get_entry(&self, namespace: Namespace, identifier: &[u8]) -> Option<&Vec<u8>> {
        let kh = state_key_hash(namespace, identifier);
        self.smt.get(&kh)
    }

    /// Supprime une entrée brute.
    pub fn remove_entry(&mut self, namespace: Namespace, identifier: &[u8]) -> Option<Vec<u8>> {
        let kh = state_key_hash(namespace, identifier);
        self.smt.remove(&kh)
    }

    // --- Comptes natifs (typed accessors) -----------------------------------

    /// Lit un compte natif.
    #[must_use]
    pub fn get_account(&self, address: &NativeAddress) -> Option<NativeAccount> {
        let bytes = self.get_entry(Namespace::NativeAccount, address.as_bytes())?;
        NativeAccount::decode_exact(bytes).ok()
    }

    /// Vrai si un compte natif existe.
    #[must_use]
    pub fn account_exists(&self, address: &NativeAddress) -> bool {
        self.get_account(address).is_some()
    }

    /// Écrit un compte natif. Le remplace s'il existe déjà.
    pub fn set_account(&mut self, account: NativeAccount) {
        let address = account.address;
        let bytes = account.encode_to_vec();
        self.put_entry(Namespace::NativeAccount, address.as_bytes(), bytes);
    }

    /// Solde d'une adresse. Retourne `Amount::ZERO` si le compte n'existe pas.
    #[must_use]
    pub fn balance_of(&self, address: &NativeAddress) -> Amount {
        self.get_account(address)
            .map_or(Amount::ZERO, |a| a.balance)
    }

    /// Nonce d'une adresse. Retourne `0` si le compte n'existe pas.
    #[must_use]
    pub fn nonce_of(&self, address: &NativeAddress) -> u64 {
        self.get_account(address).map_or(0, |a| a.nonce)
    }

    /// Clé publique enregistrée d'un compte.
    ///
    /// Retourne `None` si le compte n'existe pas, ou s'il existe sous forme
    /// « fantôme » (`PublicKey::ZERO`).
    #[must_use]
    pub fn public_key_of(&self, address: &NativeAddress) -> Option<PublicKey> {
        self.get_account(address)
            .filter(NativeAccount::has_registered_public_key)
            .map(|a| a.public_key)
    }

    /// Crée un `NativeAccount` « fantôme » : compte sans clé enregistrée.
    fn ghost_account(address: NativeAddress) -> NativeAccount {
        NativeAccount {
            address,
            public_key: PublicKey::ZERO,
            balance: Amount::ZERO,
            nonce: 0,
        }
    }

    /// Crédite une adresse, en créant un compte « fantôme » si nécessaire.
    pub fn credit(&mut self, address: NativeAddress, amount: Amount) -> Result<(), StateError> {
        let mut acc = self
            .get_account(&address)
            .unwrap_or_else(|| Self::ghost_account(address));
        acc.balance = acc
            .balance
            .checked_add(amount)
            .ok_or(StateError::BalanceOverflow { address })?;
        self.set_account(acc);
        Ok(())
    }

    /// Débite une adresse.
    pub fn debit(&mut self, address: NativeAddress, amount: Amount) -> Result<(), StateError> {
        let mut acc = self
            .get_account(&address)
            .unwrap_or_else(|| Self::ghost_account(address));
        let available = acc.balance;
        acc.balance = available
            .checked_sub(amount)
            .ok_or(StateError::InsufficientBalance {
                address,
                requested: amount.base_units(),
                available: available.base_units(),
            })?;
        self.set_account(acc);
        Ok(())
    }

    /// Incrémente le nonce d'une adresse.
    pub fn bump_nonce(&mut self, address: NativeAddress) -> Result<(), StateError> {
        let mut acc = self
            .get_account(&address)
            .unwrap_or_else(|| Self::ghost_account(address));
        acc.nonce = acc
            .nonce
            .checked_add(1)
            .ok_or(StateError::NonceOverflow { address })?;
        self.set_account(acc);
        Ok(())
    }

    /// Applique un transfert `from → to`.
    ///
    /// Si `from == to` ou `amount.is_zero()`, aucune mutation nette.
    pub fn apply_transfer(
        &mut self,
        from: NativeAddress,
        to: NativeAddress,
        amount: Amount,
    ) -> Result<(), StateError> {
        let from_balance = self.balance_of(&from);
        if from_balance < amount {
            return Err(StateError::InsufficientBalance {
                address: from,
                requested: amount.base_units(),
                available: from_balance.base_units(),
            });
        }

        if from == to || amount.is_zero() {
            return Ok(());
        }

        self.debit(from, amount)?;
        match self.credit(to, amount) {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = self.credit(from, amount);
                Err(e)
            }
        }
    }

    /// Enregistre la clé publique d'un compte « fantôme », l'activant.
    ///
    /// Voir la documentation de `sango-tx` pour la règle de bootstrap.
    pub fn set_public_key(
        &mut self,
        address: NativeAddress,
        public_key: PublicKey,
    ) -> Result<(), StateError> {
        if public_key.is_zero() {
            return Err(StateError::PublicKeyIsZero);
        }
        if derive_native_address(&public_key) != address {
            return Err(StateError::PublicKeyDoesNotMatchAddress { address });
        }
        let mut acc = self
            .get_account(&address)
            .ok_or(StateError::AccountNotFound { address })?;
        if acc.has_registered_public_key() {
            return Err(StateError::PublicKeyAlreadyRegistered { address });
        }
        acc.public_key = public_key;
        self.set_account(acc);
        Ok(())
    }

    // --- Metadata : compteurs globaux ---------------------------------------

    /// Cumul des SANGO brûlés, en base units.
    ///
    /// Retourne `Amount::ZERO` si aucune entrée n'a encore été écrite
    /// (cas normal d'un état initial).
    #[must_use]
    pub fn total_burned(&self) -> Amount {
        match self.get_entry(Namespace::Metadata, &[MetadataKey::TotalBurned.tag()]) {
            Some(bytes) => u128::decode_exact(bytes)
                .map(Amount::from_base_units)
                .unwrap_or(Amount::ZERO),
            None => Amount::ZERO,
        }
    }

    /// Cumul du gas consommé.
    ///
    /// Retourne `0` si aucune entrée n'a encore été écrite.
    #[must_use]
    pub fn total_gas_used(&self) -> u64 {
        match self.get_entry(Namespace::Metadata, &[MetadataKey::TotalGasUsed.tag()]) {
            Some(bytes) => u64::decode_exact(bytes).unwrap_or(0),
            None => 0,
        }
    }

    /// Ajoute un montant au cumul des SANGO brûlés.
    ///
    /// # Erreurs
    ///
    /// Retourne [`StateError::TotalBurnedOverflow`] si le cumul dépasserait
    /// `u128::MAX`.
    pub fn add_burned(&mut self, amount: Amount) -> Result<(), StateError> {
        let current = self.total_burned().base_units();
        let delta = amount.base_units();
        let new = current
            .checked_add(delta)
            .ok_or(StateError::TotalBurnedOverflow { current, delta })?;
        let bytes = Amount::from_base_units(new).encode_to_vec();
        self.put_entry(
            Namespace::Metadata,
            &[MetadataKey::TotalBurned.tag()],
            bytes,
        );
        Ok(())
    }

    /// Ajoute un montant au cumul du gas consommé.
    ///
    /// # Erreurs
    ///
    /// Retourne [`StateError::TotalGasUsedOverflow`] si le cumul dépasserait
    /// `u64::MAX`.
    pub fn add_gas_used(&mut self, gas: u64) -> Result<(), StateError> {
        let current = self.total_gas_used();
        let new = current
            .checked_add(gas)
            .ok_or(StateError::TotalGasUsedOverflow {
                current,
                delta: gas,
            })?;
        let bytes = new.encode_to_vec();
        self.put_entry(
            Namespace::Metadata,
            &[MetadataKey::TotalGasUsed.tag()],
            bytes,
        );
        Ok(())
    }

    /// Calcule l'offre existante :
    ///
    /// ```text
    /// current_supply = initial_supply − total_burned
    /// ```
    ///
    /// Retourne `None` si `total_burned > initial_supply`, ce qui signalerait
    /// une incohérence (ne devrait jamais arriver : `total_burned` est un
    /// cumul de frais prélevés, donc ≤ supply en circulation au moment du
    /// prélèvement).
    #[must_use]
    pub fn current_supply(&self, initial_supply: Amount) -> Option<Amount> {
        initial_supply.checked_sub(self.total_burned())
    }

    /// Racine de l'état vide (constante normative).
    #[must_use]
    pub fn empty_root() -> Hash32 {
        empty_root()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sango_crypto::NativeKeypair;

    fn addr(b: u8) -> NativeAddress {
        NativeAddress::from_bytes([b; 20])
    }

    fn ghost(b: u8, balance_units: u128, nonce: u64) -> NativeAccount {
        NativeAccount {
            address: addr(b),
            public_key: PublicKey::ZERO,
            balance: Amount::from_base_units(balance_units),
            nonce,
        }
    }

    // --- Tests existants ----------------------------------------------------

    #[test]
    fn empty_state_is_empty() {
        let s = NativeState::new();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn empty_state_root_matches_frozen_constant() {
        assert_eq!(
            NativeState::new().native_state_root(),
            NativeState::empty_root()
        );
    }

    #[test]
    fn put_account_and_get() {
        let mut s = NativeState::new();
        let a = ghost(0xaa, 1_000_000, 0);
        s.set_account(a);
        assert!(s.account_exists(&addr(0xaa)));
        assert_eq!(s.get_account(&addr(0xaa)), Some(a));
    }

    #[test]
    fn default_balance_is_zero() {
        let s = NativeState::new();
        assert_eq!(s.balance_of(&addr(0xaa)), Amount::ZERO);
        assert_eq!(s.nonce_of(&addr(0xaa)), 0);
    }

    #[test]
    fn credit_creates_ghost_account() {
        let mut s = NativeState::new();
        s.credit(addr(0xaa), Amount::from_base_units(500)).unwrap();
        let acc = s.get_account(&addr(0xaa)).unwrap();
        assert_eq!(acc.balance, Amount::from_base_units(500));
        assert!(!acc.has_registered_public_key());
    }

    #[test]
    fn debit_requires_sufficient_balance() {
        let mut s = NativeState::new();
        s.credit(addr(0xaa), Amount::from_base_units(500)).unwrap();
        let err = s
            .debit(addr(0xaa), Amount::from_base_units(501))
            .unwrap_err();
        assert!(matches!(err, StateError::InsufficientBalance { .. }));
        assert_eq!(s.balance_of(&addr(0xaa)), Amount::from_base_units(500));
    }

    #[test]
    fn credit_overflow_rejected() {
        let mut s = NativeState::new();
        s.set_account(ghost(0xaa, u128::MAX, 0));
        let err = s
            .credit(addr(0xaa), Amount::from_base_units(1))
            .unwrap_err();
        assert!(matches!(err, StateError::BalanceOverflow { .. }));
    }

    #[test]
    fn bump_nonce_overflow_rejected() {
        let mut s = NativeState::new();
        s.set_account(ghost(0xaa, 0, u64::MAX));
        let err = s.bump_nonce(addr(0xaa)).unwrap_err();
        assert!(matches!(err, StateError::NonceOverflow { .. }));
    }

    #[test]
    fn transfer_moves_funds() {
        let mut s = NativeState::new();
        s.credit(addr(0xaa), Amount::from_base_units(1_000))
            .unwrap();
        s.apply_transfer(addr(0xaa), addr(0xbb), Amount::from_base_units(400))
            .unwrap();
        assert_eq!(s.balance_of(&addr(0xaa)), Amount::from_base_units(600));
        assert_eq!(s.balance_of(&addr(0xbb)), Amount::from_base_units(400));
    }

    #[test]
    fn transfer_self_is_noop() {
        let mut s = NativeState::new();
        s.credit(addr(0xaa), Amount::from_base_units(1_000))
            .unwrap();
        s.apply_transfer(addr(0xaa), addr(0xaa), Amount::from_base_units(400))
            .unwrap();
        assert_eq!(s.balance_of(&addr(0xaa)), Amount::from_base_units(1_000));
    }

    #[test]
    fn transfer_insufficient_funds() {
        let mut s = NativeState::new();
        s.credit(addr(0xaa), Amount::from_base_units(100)).unwrap();
        let err = s
            .apply_transfer(addr(0xaa), addr(0xbb), Amount::from_base_units(200))
            .unwrap_err();
        assert!(matches!(err, StateError::InsufficientBalance { .. }));
        assert_eq!(s.balance_of(&addr(0xaa)), Amount::from_base_units(100));
        assert_eq!(s.balance_of(&addr(0xbb)), Amount::ZERO);
    }

    #[test]
    fn transfer_zero_is_noop() {
        let mut s = NativeState::new();
        s.credit(addr(0xaa), Amount::from_base_units(100)).unwrap();
        s.apply_transfer(addr(0xaa), addr(0xbb), Amount::ZERO)
            .unwrap();
        assert_eq!(s.balance_of(&addr(0xaa)), Amount::from_base_units(100));
        assert!(!s.account_exists(&addr(0xbb)));
    }

    #[test]
    fn root_depends_on_content() {
        let mut a = NativeState::new();
        a.credit(addr(0xaa), Amount::from_base_units(100)).unwrap();
        let mut b = NativeState::new();
        b.credit(addr(0xaa), Amount::from_base_units(101)).unwrap();
        assert_ne!(a.native_state_root(), b.native_state_root());
    }

    #[test]
    fn root_is_insertion_order_invariant() {
        let mut a = NativeState::new();
        a.credit(addr(0xaa), Amount::from_base_units(100)).unwrap();
        a.credit(addr(0xbb), Amount::from_base_units(200)).unwrap();
        a.credit(addr(0xcc), Amount::from_base_units(300)).unwrap();

        let mut b = NativeState::new();
        b.credit(addr(0xcc), Amount::from_base_units(300)).unwrap();
        b.credit(addr(0xaa), Amount::from_base_units(100)).unwrap();
        b.credit(addr(0xbb), Amount::from_base_units(200)).unwrap();

        assert_eq!(a.native_state_root(), b.native_state_root());
    }

    #[test]
    fn key_hash_uses_namespace() {
        let id = b"identifier";
        let h_account = state_key_hash(Namespace::NativeAccount, id);
        let h_validator = state_key_hash(Namespace::Validator, id);
        assert_ne!(h_account, h_validator);
    }

    #[test]
    fn key_hash_is_deterministic() {
        let id = b"identifier";
        assert_eq!(
            state_key_hash(Namespace::NativeAccount, id),
            state_key_hash(Namespace::NativeAccount, id),
        );
    }

    #[test]
    fn public_key_of_ghost_is_none() {
        let mut s = NativeState::new();
        s.credit(addr(0xaa), Amount::from_base_units(500)).unwrap();
        assert_eq!(s.public_key_of(&addr(0xaa)), None);
    }

    #[test]
    fn public_key_of_registered_account_is_some() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let pk = kp.public_key();
        let account = NativeAccount::from_public_key(pk, Amount::from_base_units(1_000), 0);
        let address = account.address;
        let mut s = NativeState::new();
        s.set_account(account);
        assert_eq!(s.public_key_of(&address), Some(pk));
    }

    #[test]
    fn public_key_of_missing_is_none() {
        let s = NativeState::new();
        assert_eq!(s.public_key_of(&addr(0xaa)), None);
    }

    #[test]
    fn bump_nonce_preserves_public_key() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let pk = kp.public_key();
        let account = NativeAccount::from_public_key(pk, Amount::from_base_units(1_000), 0);
        let address = account.address;
        let mut s = NativeState::new();
        s.set_account(account);
        s.bump_nonce(address).unwrap();
        let after = s.get_account(&address).unwrap();
        assert_eq!(after.public_key, pk);
        assert_eq!(after.nonce, 1);
    }

    #[test]
    fn credit_preserves_public_key() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let pk = kp.public_key();
        let account = NativeAccount::from_public_key(pk, Amount::from_base_units(1_000), 0);
        let address = account.address;
        let mut s = NativeState::new();
        s.set_account(account);
        s.credit(address, Amount::from_base_units(500)).unwrap();
        let after = s.get_account(&address).unwrap();
        assert_eq!(after.public_key, pk);
        assert_eq!(after.balance, Amount::from_base_units(1_500));
    }

    #[test]
    fn debit_preserves_public_key() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let pk = kp.public_key();
        let account = NativeAccount::from_public_key(pk, Amount::from_base_units(1_000), 0);
        let address = account.address;
        let mut s = NativeState::new();
        s.set_account(account);
        s.debit(address, Amount::from_base_units(400)).unwrap();
        let after = s.get_account(&address).unwrap();
        assert_eq!(after.public_key, pk);
        assert_eq!(after.balance, Amount::from_base_units(600));
    }

    #[test]
    fn derive_native_address_is_used_by_from_public_key() {
        let kp = NativeKeypair::from_seed([0x77; 32]);
        let pk = kp.public_key();
        let acc = NativeAccount::from_public_key(pk, Amount::ZERO, 0);
        assert_eq!(acc.address, derive_native_address(&pk));
    }

    #[test]
    fn set_public_key_activates_ghost() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let pk = kp.public_key();
        let address = derive_native_address(&pk);
        let mut s = NativeState::new();
        s.credit(address, Amount::from_base_units(1_000)).unwrap();
        assert_eq!(s.public_key_of(&address), None);
        s.set_public_key(address, pk).unwrap();
        assert_eq!(s.public_key_of(&address), Some(pk));
        let acc = s.get_account(&address).unwrap();
        assert!(acc.has_registered_public_key());
    }

    #[test]
    fn set_public_key_changes_smt_root() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let pk = kp.public_key();
        let address = derive_native_address(&pk);
        let mut s = NativeState::new();
        s.credit(address, Amount::from_base_units(500)).unwrap();
        let root_before = s.native_state_root();
        s.set_public_key(address, pk).unwrap();
        let root_after = s.native_state_root();
        assert_ne!(root_before, root_after);
    }

    #[test]
    fn set_public_key_preserves_balance_and_nonce() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let pk = kp.public_key();
        let address = derive_native_address(&pk);
        let mut s = NativeState::new();
        s.set_account(NativeAccount {
            address,
            public_key: PublicKey::ZERO,
            balance: Amount::from_base_units(777),
            nonce: 3,
        });
        s.set_public_key(address, pk).unwrap();
        let acc = s.get_account(&address).unwrap();
        assert_eq!(acc.public_key, pk);
        assert_eq!(acc.balance, Amount::from_base_units(777));
        assert_eq!(acc.nonce, 3);
    }

    #[test]
    fn set_public_key_rejects_missing_account() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let pk = kp.public_key();
        let address = derive_native_address(&pk);
        let mut s = NativeState::new();
        let err = s.set_public_key(address, pk).unwrap_err();
        assert!(matches!(err, StateError::AccountNotFound { .. }));
    }

    #[test]
    fn set_public_key_rejects_zero() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let address = derive_native_address(&kp.public_key());
        let mut s = NativeState::new();
        s.credit(address, Amount::from_base_units(100)).unwrap();
        let err = s.set_public_key(address, PublicKey::ZERO).unwrap_err();
        assert_eq!(err, StateError::PublicKeyIsZero);
    }

    #[test]
    fn set_public_key_rejects_derivation_mismatch() {
        let kp1 = NativeKeypair::from_seed([0x42; 32]);
        let kp2 = NativeKeypair::from_seed([0x43; 32]);
        let address = derive_native_address(&kp1.public_key());
        let mut s = NativeState::new();
        s.credit(address, Amount::from_base_units(100)).unwrap();
        let err = s.set_public_key(address, kp2.public_key()).unwrap_err();
        assert!(matches!(
            err,
            StateError::PublicKeyDoesNotMatchAddress { .. }
        ));
    }

    #[test]
    fn set_public_key_rejects_double_registration() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let pk = kp.public_key();
        let address = derive_native_address(&pk);
        let mut s = NativeState::new();
        s.set_account(NativeAccount::from_public_key(
            pk,
            Amount::from_base_units(1_000),
            0,
        ));
        let err = s.set_public_key(address, pk).unwrap_err();
        assert!(matches!(err, StateError::PublicKeyAlreadyRegistered { .. }));
    }

    // --- Metadata : total_burned / total_gas_used ---------------------------

    #[test]
    fn initial_total_burned_is_zero() {
        let s = NativeState::new();
        assert_eq!(s.total_burned(), Amount::ZERO);
    }

    #[test]
    fn initial_total_gas_used_is_zero() {
        let s = NativeState::new();
        assert_eq!(s.total_gas_used(), 0);
    }

    #[test]
    fn add_burned_accumulates() {
        let mut s = NativeState::new();
        s.add_burned(Amount::from_base_units(100)).unwrap();
        assert_eq!(s.total_burned(), Amount::from_base_units(100));
        s.add_burned(Amount::from_base_units(250)).unwrap();
        assert_eq!(s.total_burned(), Amount::from_base_units(350));
    }

    #[test]
    fn add_gas_used_accumulates() {
        let mut s = NativeState::new();
        s.add_gas_used(21_000).unwrap();
        assert_eq!(s.total_gas_used(), 21_000);
        s.add_gas_used(42_000).unwrap();
        assert_eq!(s.total_gas_used(), 63_000);
    }

    #[test]
    fn add_burned_changes_root() {
        let mut s = NativeState::new();
        let before = s.native_state_root();
        s.add_burned(Amount::from_base_units(1)).unwrap();
        assert_ne!(s.native_state_root(), before);
    }

    #[test]
    fn add_gas_used_changes_root() {
        let mut s = NativeState::new();
        let before = s.native_state_root();
        s.add_gas_used(1).unwrap();
        assert_ne!(s.native_state_root(), before);
    }

    #[test]
    fn add_burned_overflow_rejected() {
        let mut s = NativeState::new();
        s.add_burned(Amount::from_base_units(u128::MAX)).unwrap();
        let err = s.add_burned(Amount::from_base_units(1)).unwrap_err();
        assert!(matches!(err, StateError::TotalBurnedOverflow { .. }));
        // La valeur n'a pas changé.
        assert_eq!(s.total_burned(), Amount::from_base_units(u128::MAX));
    }

    #[test]
    fn add_gas_used_overflow_rejected() {
        let mut s = NativeState::new();
        s.add_gas_used(u64::MAX).unwrap();
        let err = s.add_gas_used(1).unwrap_err();
        assert!(matches!(err, StateError::TotalGasUsedOverflow { .. }));
        assert_eq!(s.total_gas_used(), u64::MAX);
    }

    #[test]
    fn metadata_root_is_insertion_order_invariant() {
        let mut a = NativeState::new();
        a.add_burned(Amount::from_base_units(100)).unwrap();
        a.add_gas_used(21_000).unwrap();

        let mut b = NativeState::new();
        b.add_gas_used(21_000).unwrap();
        b.add_burned(Amount::from_base_units(100)).unwrap();

        assert_eq!(a.native_state_root(), b.native_state_root());
    }

    #[test]
    fn metadata_is_independent_of_accounts() {
        let mut s = NativeState::new();
        s.credit(addr(0xaa), Amount::from_base_units(1_000))
            .unwrap();
        s.add_burned(Amount::from_base_units(50)).unwrap();
        // total_burned n'est pas affecté par un crédit ultérieur.
        s.credit(addr(0xbb), Amount::from_base_units(500)).unwrap();
        assert_eq!(s.total_burned(), Amount::from_base_units(50));
        assert_eq!(s.balance_of(&addr(0xaa)), Amount::from_base_units(1_000));
        assert_eq!(s.balance_of(&addr(0xbb)), Amount::from_base_units(500));
    }

    #[test]
    fn current_supply_subtracts_burned() {
        let initial = Amount::from_sango(1_000_000_000).unwrap();
        let mut s = NativeState::new();
        s.add_burned(Amount::from_sango(1_000).unwrap()).unwrap();
        let current = s.current_supply(initial).unwrap();
        assert_eq!(
            current.base_units(),
            initial.base_units() - Amount::from_sango(1_000).unwrap().base_units()
        );
    }

    #[test]
    fn current_supply_no_burn_is_initial() {
        let initial = Amount::from_sango(1_000_000_000).unwrap();
        let s = NativeState::new();
        assert_eq!(s.current_supply(initial), Some(initial));
    }

    #[test]
    fn current_supply_underflow_returns_none() {
        let initial = Amount::from_base_units(100);
        let mut s = NativeState::new();
        s.add_burned(Amount::from_base_units(101)).unwrap();
        assert_eq!(s.current_supply(initial), None);
    }

    #[test]
    fn total_burned_does_not_affect_account_balance() {
        let mut s = NativeState::new();
        s.credit(addr(0xaa), Amount::from_base_units(1_000))
            .unwrap();
        let before = s.balance_of(&addr(0xaa));
        s.add_burned(Amount::from_base_units(500)).unwrap();
        assert_eq!(s.balance_of(&addr(0xaa)), before);
    }

    #[test]
    fn metadata_survives_clone() {
        let mut s = NativeState::new();
        s.add_burned(Amount::from_base_units(42)).unwrap();
        s.add_gas_used(100).unwrap();
        let clone = s.clone();
        assert_eq!(clone.total_burned(), Amount::from_base_units(42));
        assert_eq!(clone.total_gas_used(), 100);
        assert_eq!(clone.native_state_root(), s.native_state_root());
    }
}
