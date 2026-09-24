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
//! - [`MetadataKey::TotalGasUsed`] : cumul du gas consommé ;
//! - [`MetadataKey::TotalPosRewards`] : cumul des récompenses PoS ;
//! - [`MetadataKey::NextUnbondingId`] : compteur monotone d'unbondings.
//!
//! Ces valeurs font partie du `native_state_root`.

use sango_codec::{Decode, Encode};
use sango_crypto::{derive_native_address, domain, hash_domain};
use sango_primitives::{Amount, Hash32, NativeAddress, PublicKey};
use sango_types::{NativeAccount, PendingUnbonding};

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

    /// Vue itérable sur toutes les entrées de l'état, dans l'ordre
    /// byte-lex croissant des `key_hash`.
    ///
    /// Utilisé par la couche node pour calculer un diff d'état et le
    /// persister.
    pub fn iter_entries(&self) -> impl Iterator<Item = (&Hash32, &Vec<u8>)> {
        self.smt.iter()
    }

    /// Restaure une entrée à partir de son `key_hash` déjà calculé.
    ///
    /// Utilisé au chargement initial de la base : les clés sont stockées
    /// sous leur forme hashée, et non sous leur forme logique.
    ///
    /// Cette méthode court-circuite le hashage logique `namespace ||
    /// identifier` : l'appelant doit fournir un `key_hash` obtenu par
    /// [`state_key_hash`] lors d'une exécution précédente.
    pub fn restore_entry(&mut self, key_hash: Hash32, value: Vec<u8>) {
        self.smt.insert(key_hash, value);
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

    /// Cumul des récompenses PoS distribuées depuis le genesis.
    #[must_use]
    pub fn total_pos_rewards(&self) -> Amount {
        match self.get_entry(Namespace::Metadata, &[MetadataKey::TotalPosRewards.tag()]) {
            Some(bytes) => u128::decode_exact(bytes)
                .map(Amount::from_base_units)
                .unwrap_or(Amount::ZERO),
            None => Amount::ZERO,
        }
    }

    /// Ajoute un montant au cumul des récompenses PoS.
    ///
    /// # Erreurs
    ///
    /// Retourne [`StateError::TotalBurnedOverflow`] si le cumul dépasserait
    /// `u128::MAX` (cas pathologique).
    pub fn add_pos_rewards(&mut self, amount: Amount) -> Result<(), StateError> {
        let current = self.total_pos_rewards().base_units();
        let delta = amount.base_units();
        let new = current
            .checked_add(delta)
            .ok_or(StateError::TotalBurnedOverflow { current, delta })?;
        let bytes = Amount::from_base_units(new).encode_to_vec();
        self.put_entry(
            Namespace::Metadata,
            &[MetadataKey::TotalPosRewards.tag()],
            bytes,
        );
        Ok(())
    }

    // --- Unbondings en attente ----------------------------------------------

    /// Prochain identifiant d'unbonding à allouer (`0` si aucun).
    #[must_use]
    pub fn next_unbonding_id(&self) -> u64 {
        match self.get_entry(Namespace::Metadata, &[MetadataKey::NextUnbondingId.tag()]) {
            Some(bytes) => u64::decode_exact(bytes).unwrap_or(0),
            None => 0,
        }
    }

    /// Alloue un nouvel identifiant monotone et l'incrémente dans l'état.
    ///
    /// # Erreurs
    ///
    /// [`StateError::UnbondingIdOverflow`] si `next_unbonding_id == u64::MAX`.
    pub fn alloc_unbonding_id(&mut self) -> Result<u64, StateError> {
        let id = self.next_unbonding_id();
        let new = id.checked_add(1).ok_or(StateError::UnbondingIdOverflow)?;
        self.put_entry(
            Namespace::Metadata,
            &[MetadataKey::NextUnbondingId.tag()],
            new.encode_to_vec(),
        );
        Ok(id)
    }

    /// Écrit un événement d'unbonding en attente.
    pub fn put_pending_unbonding(&mut self, p: PendingUnbonding) {
        let id_bytes = p.id.to_be_bytes();
        let value = p.encode_to_vec();
        self.put_entry(Namespace::Unbonding, &id_bytes, value);
    }

    /// Lit un événement d'unbonding par id.
    #[must_use]
    pub fn get_pending_unbonding(&self, id: u64) -> Option<PendingUnbonding> {
        let bytes = self.get_entry(Namespace::Unbonding, &id.to_be_bytes())?;
        PendingUnbonding::decode_exact(bytes).ok()
    }

    /// Supprime un événement d'unbonding.
    pub fn remove_pending_unbonding(&mut self, id: u64) -> Option<Vec<u8>> {
        self.remove_entry(Namespace::Unbonding, &id.to_be_bytes())
    }

    /// Énumère tous les unbondings en attente, triés par id croissant.
    ///
    /// Utilise le même filtrage cryptographique que [`Self::all_validators`] :
    /// on décode une valeur, puis on vérifie que son `id` reconstruit bien la
    /// clé SMT attendue. Aucune ambiguïté possible avec un autre namespace.
    #[must_use]
    pub fn iter_pending_unbondings(&self) -> Vec<PendingUnbonding> {
        let mut out = Vec::new();
        for (key_hash, value) in self.smt.iter() {
            if let Ok(p) = PendingUnbonding::decode_exact(value) {
                let expected = state_key_hash(Namespace::Unbonding, &p.id.to_be_bytes());
                if expected == *key_hash {
                    out.push(p);
                }
            }
        }
        out.sort_by_key(|p| p.id);
        out
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

    // --- Validateurs --------------------------------------------------------

    /// Lit les informations d'un validateur.
    #[must_use]
    pub fn get_validator(&self, address: &NativeAddress) -> Option<sango_types::ValidatorInfo> {
        let bytes = self.get_entry(Namespace::Validator, address.as_bytes())?;
        sango_types::ValidatorInfo::decode_exact(bytes).ok()
    }

    /// Vrai si un validateur est enregistré.
    #[must_use]
    pub fn validator_exists(&self, address: &NativeAddress) -> bool {
        self.get_validator(address).is_some()
    }

    /// Écrit les informations d'un validateur (remplace si existant).
    pub fn set_validator(&mut self, info: sango_types::ValidatorInfo) {
        let address = info.address;
        let bytes = info.encode_to_vec();
        self.put_entry(Namespace::Validator, address.as_bytes(), bytes);
    }

    /// Supprime l'enregistrement d'un validateur.
    pub fn remove_validator(&mut self, address: &NativeAddress) -> Option<Vec<u8>> {
        self.remove_entry(Namespace::Validator, address.as_bytes())
    }

    // --- Délégations --------------------------------------------------------

    /// Clé logique d'une délégation : `delegator || validator`.
    fn delegation_identifier(delegator: &NativeAddress, validator: &NativeAddress) -> [u8; 40] {
        let mut key = [0u8; 40];
        key[..20].copy_from_slice(delegator.as_bytes());
        key[20..].copy_from_slice(validator.as_bytes());
        key
    }

    /// Lit une délégation.
    #[must_use]
    pub fn get_delegation(
        &self,
        delegator: &NativeAddress,
        validator: &NativeAddress,
    ) -> Option<sango_types::Delegation> {
        let key = Self::delegation_identifier(delegator, validator);
        let bytes = self.get_entry(Namespace::Delegation, &key)?;
        sango_types::Delegation::decode_exact(bytes).ok()
    }

    /// Écrit une délégation (remplace si existante).
    pub fn set_delegation(&mut self, d: sango_types::Delegation) {
        let key = Self::delegation_identifier(&d.delegator, &d.validator);
        let bytes = d.encode_to_vec();
        self.put_entry(Namespace::Delegation, &key, bytes);
    }

    /// Supprime une délégation.
    pub fn remove_delegation(
        &mut self,
        delegator: &NativeAddress,
        validator: &NativeAddress,
    ) -> Option<Vec<u8>> {
        let key = Self::delegation_identifier(delegator, validator);
        self.remove_entry(Namespace::Delegation, &key)
    }

    // --- Énumération (filtrage cryptographique) -----------------------------

    /// Liste tous les validateurs enregistrés.
    ///
    /// Pour chaque entrée du SMT, on tente de décoder un `ValidatorInfo`,
    /// puis on vérifie que `state_key_hash(Validator, info.address)`
    /// correspond bien au `key_hash` de l'entrée. C'est une vérification
    /// **cryptographique** : aucune ambiguïté possible avec un compte ou
    /// une délégation.
    #[must_use]
    pub fn all_validators(&self) -> Vec<sango_types::ValidatorInfo> {
        let mut out = Vec::new();
        for (key_hash, value) in self.smt.iter() {
            if let Ok(info) = sango_types::ValidatorInfo::decode_exact(value) {
                let expected = state_key_hash(Namespace::Validator, info.address.as_bytes());
                if expected == *key_hash {
                    out.push(info);
                }
            }
        }
        out
    }

    /// Liste toutes les délégations vers un validateur donné.
    #[must_use]
    pub fn delegations_for(&self, validator: &NativeAddress) -> Vec<sango_types::Delegation> {
        let mut out = Vec::new();
        for (key_hash, value) in self.smt.iter() {
            if let Ok(d) = sango_types::Delegation::decode_exact(value) {
                if d.validator != *validator {
                    continue;
                }
                let key = Self::delegation_identifier(&d.delegator, &d.validator);
                let expected = state_key_hash(Namespace::Delegation, &key);
                if expected == *key_hash {
                    out.push(d);
                }
            }
        }
        out
    }

    // --- Evidence ----------------------------------------------------------

    /// Lit un enregistrement d'evidence déjà appliquée.
    #[must_use]
    pub fn get_evidence(&self, evidence_id: &Hash32) -> Option<sango_types::EvidenceRecord> {
        let bytes = self.get_entry(Namespace::Evidence, evidence_id.as_bytes())?;
        sango_types::EvidenceRecord::decode_exact(bytes).ok()
    }

    /// Enregistre une evidence comme appliquée.
    pub fn set_evidence(&mut self, record: sango_types::EvidenceRecord) {
        let key = record.evidence_id;
        let bytes = record.encode_to_vec();
        self.put_entry(Namespace::Evidence, key.as_bytes(), bytes);
    }

    /// Vrai si une evidence a déjà été appliquée.
    #[must_use]
    pub fn has_evidence(&self, evidence_id: &Hash32) -> bool {
        self.get_evidence(evidence_id).is_some()
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

    // --- Tests de base ------------------------------------------------------

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

    // --- Pending unbondings -------------------------------------------------

    #[test]
    fn initial_next_unbonding_id_is_zero() {
        let s = NativeState::new();
        assert_eq!(s.next_unbonding_id(), 0);
    }

    #[test]
    fn alloc_unbonding_id_is_monotone() {
        let mut s = NativeState::new();
        assert_eq!(s.alloc_unbonding_id().unwrap(), 0);
        assert_eq!(s.alloc_unbonding_id().unwrap(), 1);
        assert_eq!(s.alloc_unbonding_id().unwrap(), 2);
        assert_eq!(s.next_unbonding_id(), 3);
    }

    #[test]
    fn pending_unbonding_roundtrip() {
        let mut s = NativeState::new();
        let id = s.alloc_unbonding_id().unwrap();
        let p = PendingUnbonding {
            id,
            delegator: addr(0xaa),
            validator: addr(0xbb),
            amount: Amount::from_sango(1_000).unwrap(),
            mature_at: 1_800_000_000,
        };
        s.put_pending_unbonding(p);
        assert_eq!(s.get_pending_unbonding(id), Some(p));
    }

    #[test]
    fn iter_pending_unbondings_is_sorted_by_id() {
        let mut s = NativeState::new();
        for i in 0..5 {
            let id = s.alloc_unbonding_id().unwrap();
            s.put_pending_unbonding(PendingUnbonding {
                id,
                delegator: addr(0xaa),
                validator: addr(0xbb),
                amount: Amount::from_base_units(100 * (i as u128 + 1)),
                mature_at: 1_800_000_000 + i as u64,
            });
        }
        let all = s.iter_pending_unbondings();
        assert_eq!(all.len(), 5);
        for (i, p) in all.iter().enumerate() {
            assert_eq!(p.id, i as u64);
        }
    }

    #[test]
    fn remove_pending_unbonding_removes_entry() {
        let mut s = NativeState::new();
        let id = s.alloc_unbonding_id().unwrap();
        s.put_pending_unbonding(PendingUnbonding {
            id,
            delegator: addr(0xaa),
            validator: addr(0xbb),
            amount: Amount::from_base_units(1),
            mature_at: 1_800_000_000,
        });
        assert!(s.get_pending_unbonding(id).is_some());
        s.remove_pending_unbonding(id);
        assert!(s.get_pending_unbonding(id).is_none());
        assert!(s.iter_pending_unbondings().is_empty());
    }

    #[test]
    fn next_unbonding_id_survives_clone() {
        let mut s = NativeState::new();
        s.alloc_unbonding_id().unwrap();
        s.alloc_unbonding_id().unwrap();
        let c = s.clone();
        assert_eq!(c.next_unbonding_id(), 2);
    }

    // --- Staking ------------------------------------------------------------

    #[test]
    fn validator_absent_returns_none() {
        let s = NativeState::new();
        assert!(s.get_validator(&addr(0xaa)).is_none());
        assert!(!s.validator_exists(&addr(0xaa)));
    }

    #[test]
    fn validator_roundtrip() {
        use sango_types::ValidatorInfo;
        let mut s = NativeState::new();
        let v = ValidatorInfo {
            address: addr(0xaa),
            public_key: PublicKey::from_bytes([0x01; 32]),
            self_stake: Amount::from_sango(100_000).unwrap(),
            total_delegated: Amount::ZERO,
            commission_bps: 700,
            pending_commission_bps: None,
            pending_commission_at: None,
            jailed: false,
            jailed_until: None,
            downtime_window_start: 0,
            downtime_missed: 0,
        };
        s.set_validator(v);
        assert!(s.validator_exists(&addr(0xaa)));
        assert_eq!(s.get_validator(&addr(0xaa)), Some(v));
    }

    #[test]
    fn delegation_absent_returns_none() {
        let s = NativeState::new();
        assert!(s.get_delegation(&addr(0xbb), &addr(0xaa)).is_none());
    }

    #[test]
    fn delegation_roundtrip() {
        use sango_types::Delegation;
        let mut s = NativeState::new();
        let d = Delegation {
            delegator: addr(0xbb),
            validator: addr(0xaa),
            bonded: Amount::from_sango(1_000).unwrap(),
            unbonding: Amount::ZERO,
            unbonding_until: None,
            pending_rewards: Amount::ZERO,
        };
        s.set_delegation(d);
        assert_eq!(s.get_delegation(&addr(0xbb), &addr(0xaa)), Some(d));
    }

    #[test]
    fn delegation_keyed_by_delegator_and_validator() {
        use sango_types::Delegation;
        let mut s = NativeState::new();
        let d = Delegation::empty(addr(0xbb), addr(0xaa));
        s.set_delegation(d);
        assert!(s.get_delegation(&addr(0xcc), &addr(0xaa)).is_none());
        assert!(s.get_delegation(&addr(0xbb), &addr(0xcc)).is_none());
    }

    #[test]
    fn validator_staking_does_not_touch_accounts() {
        use sango_types::ValidatorInfo;
        let mut s = NativeState::new();
        s.credit(addr(0xaa), Amount::from_sango(200_000).unwrap())
            .unwrap();
        let account_before = s.get_account(&addr(0xaa));

        s.set_validator(ValidatorInfo {
            address: addr(0xaa),
            public_key: PublicKey::from_bytes([0x01; 32]),
            self_stake: Amount::from_sango(100_000).unwrap(),
            total_delegated: Amount::ZERO,
            commission_bps: 700,
            pending_commission_bps: None,
            pending_commission_at: None,
            jailed: false,
            jailed_until: None,
            downtime_window_start: 0,
            downtime_missed: 0,
        });

        assert_eq!(s.get_account(&addr(0xaa)), account_before);
    }

    // --- Énumération / evidence ---------------------------------------------

    #[test]
    fn all_validators_returns_only_validators() {
        use sango_types::ValidatorInfo;
        let mut s = NativeState::new();
        s.credit(addr(0xaa), Amount::from_base_units(100)).unwrap();
        s.set_validator(ValidatorInfo {
            address: addr(0xbb),
            public_key: PublicKey::from_bytes([0x01; 32]),
            self_stake: Amount::from_sango(100_000).unwrap(),
            total_delegated: Amount::ZERO,
            commission_bps: 700,
            pending_commission_bps: None,
            pending_commission_at: None,
            jailed: false,
            jailed_until: None,
            downtime_window_start: 0,
            downtime_missed: 0,
        });
        let vs = s.all_validators();
        assert_eq!(vs.len(), 1);
        assert_eq!(vs[0].address, addr(0xbb));
    }

    #[test]
    fn delegations_for_filters_by_validator() {
        use sango_types::Delegation;
        let mut s = NativeState::new();
        s.set_delegation(Delegation::empty(addr(0x01), addr(0xaa)));
        s.set_delegation(Delegation::empty(addr(0x02), addr(0xaa)));
        s.set_delegation(Delegation::empty(addr(0x01), addr(0xbb)));
        let d_aa = s.delegations_for(&addr(0xaa));
        assert_eq!(d_aa.len(), 2);
        let d_bb = s.delegations_for(&addr(0xbb));
        assert_eq!(d_bb.len(), 1);
    }

    #[test]
    fn evidence_absent_returns_none() {
        let s = NativeState::new();
        let id = Hash32::from_bytes([0xab; 32]);
        assert!(s.get_evidence(&id).is_none());
        assert!(!s.has_evidence(&id));
    }

    #[test]
    fn evidence_roundtrip() {
        use sango_types::EvidenceRecord;
        let mut s = NativeState::new();
        let record = EvidenceRecord {
            evidence_id: Hash32::from_bytes([0xab; 32]),
            validator_address: addr(0xaa),
            applied_at_height: 42,
            slashed: Amount::from_base_units(12345),
        };
        s.set_evidence(record);
        assert!(s.has_evidence(&record.evidence_id));
        assert_eq!(s.get_evidence(&record.evidence_id), Some(record));
    }
}
