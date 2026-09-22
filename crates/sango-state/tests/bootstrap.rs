//! Tests d'intégration du cycle de **bootstrap** d'un compte natif.
//!
//! ## Scénario
//!
//! Un compte natif est d'abord **crédité** par un tiers (transfert entrant
//! ou allocation Genesis). Il existe alors sous forme « fantôme » : adresse,
//! solde, nonce, mais **pas** de clé publique enregistrée
//! (`public_key == PublicKey::ZERO`).
//!
//! Pour dépenser, l'utilisateur doit **activer** sa clé publique en
//! déclarant `tx.public_key = Some(pk)` dans sa première transaction. Le
//! pipeline complet est :
//!
//! ```text
//! 1. Validation   : sango_tx::validate_transaction
//! 2. Application  : NativeState::set_public_key (bootstrap)
//! 3. Consensus    : le native_state_root change
//! ```
//!
//! Ces tests vérifient l'enchaînement de ces trois étapes, sans dépendre de
//! `sango-node`.

use sango_crypto::{derive_native_address, NativeKeypair};
use sango_primitives::{Amount, ChainId32, NativeAddress, PublicKey, Signature};
use sango_state::{NativeState, StateError};
use sango_tx::{validate_transaction, SenderInfo, ValidatedTransaction, ValidationContext};
use sango_types::{NativeAccount, Transaction, TxKind};

// --- Helpers --------------------------------------------------------------

fn chain() -> ChainId32 {
    ChainId32::from_bytes([0x11; 32])
}

fn recipient() -> NativeAddress {
    NativeAddress::from_bytes([0xbb; 20])
}

/// Transaction de **bootstrap** : `public_key = Some(pk)`.
fn signed_bootstrap_transfer(
    keypair: &NativeKeypair,
    nonce: u64,
    value: u128,
    max_fee: u128,
) -> Transaction {
    let pk = keypair.public_key();
    let sender = derive_native_address(&pk);
    let tx = Transaction {
        version: 1,
        chain_id: chain(),
        nonce,
        sender,
        public_key: Some(pk),
        gas_limit: 21_000,
        max_fee,
        priority_fee: 0,
        value: Amount::from_base_units(value),
        tx_kind: TxKind::Transfer,
        recipient: Some(recipient()),
        data: Vec::new(),
        signature: Signature::ZERO,
    };
    tx.sign(keypair)
}

/// Transaction **normale** : `public_key = None`, la clé doit déjà être
/// enregistrée dans l'état.
fn signed_normal_transfer(
    keypair: &NativeKeypair,
    nonce: u64,
    value: u128,
    max_fee: u128,
) -> Transaction {
    let pk = keypair.public_key();
    let sender = derive_native_address(&pk);
    let tx = Transaction {
        version: 1,
        chain_id: chain(),
        nonce,
        sender,
        public_key: None,
        gas_limit: 21_000,
        max_fee,
        priority_fee: 0,
        value: Amount::from_base_units(value),
        tx_kind: TxKind::Transfer,
        recipient: Some(recipient()),
        data: Vec::new(),
        signature: Signature::ZERO,
    };
    tx.sign(keypair)
}

/// Reconstruit un `SenderInfo` depuis l'état, comme le ferait un mempool ou
/// un block builder.
fn sender_info_from_state(state: &NativeState, address: &NativeAddress) -> SenderInfo {
    match state.get_account(address) {
        Some(acc) => SenderInfo {
            address: acc.address,
            public_key: if acc.has_registered_public_key() {
                Some(acc.public_key)
            } else {
                None
            },
            balance: acc.balance.base_units(),
            nonce: acc.nonce,
        },
        None => SenderInfo::ghost(*address, 0, 0),
    }
}

/// Applique la partie « bootstrap » d'une transaction validée.
///
/// Dans un vrai nœud, cette étape fait partie du block applier, juste après
/// le débit des frais et le transfert.
fn apply_bootstrap(
    state: &mut NativeState,
    validated: &ValidatedTransaction,
) -> Result<(), StateError> {
    if let Some(pk) = validated.bootstrap_public_key {
        state.set_public_key(validated.sender, pk)?;
    }
    Ok(())
}

// --- Bootstrap : chemin heureux ------------------------------------------

#[test]
fn bootstrap_full_flow() {
    let kp = NativeKeypair::from_seed([0x42; 32]);
    let pk = kp.public_key();
    let sender = derive_native_address(&pk);

    // 1. Crédit initial → compte fantôme.
    let mut state = NativeState::new();
    state
        .credit(sender, Amount::from_base_units(1_000_000))
        .unwrap();
    assert!(state.account_exists(&sender));
    assert_eq!(state.public_key_of(&sender), None);

    let root_ghost = state.native_state_root();

    // 2. Tx de bootstrap signée.
    let tx = signed_bootstrap_transfer(&kp, 0, 100, 20);

    // 3. Validation.
    let info = sender_info_from_state(&state, &sender);
    assert_eq!(info.public_key, None);

    let ctx = ValidationContext {
        expected_chain_id: chain(),
        base_fee: 10,
        sender: &info,
    };
    let validated = validate_transaction(&tx, &ctx).unwrap();
    assert_eq!(validated.bootstrap_public_key, Some(pk));

    // 4. Application.
    apply_bootstrap(&mut state, &validated).unwrap();

    // 5. Vérifications.
    assert_eq!(state.public_key_of(&sender), Some(pk));
    let root_active = state.native_state_root();
    assert_ne!(root_ghost, root_active);

    let acc = state.get_account(&sender).unwrap();
    assert!(acc.has_registered_public_key());
    assert_eq!(acc.public_key, pk);
    // Le solde et le nonce ne sont pas modifiés par set_public_key.
    assert_eq!(acc.balance, Amount::from_base_units(1_000_000));
    assert_eq!(acc.nonce, 0);
}

#[test]
fn bootstrap_does_not_touch_unrelated_accounts() {
    let kp = NativeKeypair::from_seed([0x42; 32]);
    let pk = kp.public_key();
    let sender = derive_native_address(&pk);
    let other = NativeAddress::from_bytes([0xdd; 20]);

    let mut state = NativeState::new();
    state
        .credit(sender, Amount::from_base_units(1_000_000))
        .unwrap();
    state.credit(other, Amount::from_base_units(500)).unwrap();

    let other_before = state.get_account(&other).unwrap();

    let tx = signed_bootstrap_transfer(&kp, 0, 10, 20);
    let info = sender_info_from_state(&state, &sender);
    let ctx = ValidationContext {
        expected_chain_id: chain(),
        base_fee: 10,
        sender: &info,
    };
    let validated = validate_transaction(&tx, &ctx).unwrap();
    apply_bootstrap(&mut state, &validated).unwrap();

    let other_after = state.get_account(&other).unwrap();
    assert_eq!(other_before, other_after);
}

// --- Bootstrap : cas rejetés ---------------------------------------------

#[test]
fn normal_tx_on_ghost_rejected_at_validation() {
    // Compte fantôme + tx sans déclaration de clé → rejeté par sango-tx.
    let kp = NativeKeypair::from_seed([0x42; 32]);
    let pk = kp.public_key();
    let sender = derive_native_address(&pk);

    let mut state = NativeState::new();
    state
        .credit(sender, Amount::from_base_units(1_000_000))
        .unwrap();

    let tx = signed_normal_transfer(&kp, 0, 100, 20);
    let info = sender_info_from_state(&state, &sender);
    assert_eq!(info.public_key, None);

    let ctx = ValidationContext {
        expected_chain_id: chain(),
        base_fee: 10,
        sender: &info,
    };
    let err = validate_transaction(&tx, &ctx).unwrap_err();
    assert_eq!(err, sango_tx::TxValidationError::PublicKeyNotRegistered);
}

#[test]
fn set_public_key_on_missing_account_rejected() {
    let kp = NativeKeypair::from_seed([0x42; 32]);
    let pk = kp.public_key();
    let sender = derive_native_address(&pk);

    let mut state = NativeState::new();
    let err = state.set_public_key(sender, pk).unwrap_err();
    assert!(matches!(err, StateError::AccountNotFound { .. }));
}

#[test]
fn set_public_key_zero_rejected() {
    let kp = NativeKeypair::from_seed([0x42; 32]);
    let sender = derive_native_address(&kp.public_key());

    let mut state = NativeState::new();
    state.credit(sender, Amount::from_base_units(100)).unwrap();

    let err = state.set_public_key(sender, PublicKey::ZERO).unwrap_err();
    assert_eq!(err, StateError::PublicKeyIsZero);
}

#[test]
fn set_public_key_derivation_mismatch_rejected() {
    let kp1 = NativeKeypair::from_seed([0x42; 32]);
    let kp2 = NativeKeypair::from_seed([0x43; 32]);
    let sender = derive_native_address(&kp1.public_key());

    let mut state = NativeState::new();
    state.credit(sender, Amount::from_base_units(100)).unwrap();

    let err = state.set_public_key(sender, kp2.public_key()).unwrap_err();
    assert!(matches!(
        err,
        StateError::PublicKeyDoesNotMatchAddress { .. }
    ));
}

// --- Cycle de vie complet --------------------------------------------------

#[test]
fn second_tx_after_bootstrap_ok() {
    let kp = NativeKeypair::from_seed([0x42; 32]);
    let pk = kp.public_key();
    let sender = derive_native_address(&pk);

    // Bootstrap initial.
    let mut state = NativeState::new();
    state
        .credit(sender, Amount::from_base_units(1_000_000))
        .unwrap();

    let tx1 = signed_bootstrap_transfer(&kp, 0, 100, 20);
    let info1 = sender_info_from_state(&state, &sender);
    let ctx1 = ValidationContext {
        expected_chain_id: chain(),
        base_fee: 10,
        sender: &info1,
    };
    let v1 = validate_transaction(&tx1, &ctx1).unwrap();
    apply_bootstrap(&mut state, &v1).unwrap();
    // On simule le bump de nonce effectué par le block applier.
    state.bump_nonce(sender).unwrap();

    // Deuxième tx : compte actif, nonce 1, sans déclaration de clé.
    let tx2 = signed_normal_transfer(&kp, 1, 50, 20);
    let info2 = sender_info_from_state(&state, &sender);
    assert_eq!(info2.public_key, Some(pk));
    assert_eq!(info2.nonce, 1);

    let ctx2 = ValidationContext {
        expected_chain_id: chain(),
        base_fee: 10,
        sender: &info2,
    };
    let v2 = validate_transaction(&tx2, &ctx2).unwrap();
    assert_eq!(v2.bootstrap_public_key, None);
}

#[test]
fn redeclaration_of_same_key_is_noop_in_state() {
    // Un compte déjà actif peut re-déclarer la même clé dans une nouvelle
    // transaction (par exemple après un redémarrage du wallet). La
    // validation l'accepte, mais `bootstrap_public_key == None`, donc
    // l'application n'appelle pas `set_public_key`.
    let kp = NativeKeypair::from_seed([0x42; 32]);
    let pk = kp.public_key();
    let sender = derive_native_address(&pk);

    let mut state = NativeState::new();
    state.set_account(NativeAccount::from_public_key(
        pk,
        Amount::from_base_units(1_000_000),
        0,
    ));
    let root_before = state.native_state_root();

    let tx = signed_bootstrap_transfer(&kp, 0, 100, 20);
    let info = sender_info_from_state(&state, &sender);
    assert_eq!(info.public_key, Some(pk));

    let ctx = ValidationContext {
        expected_chain_id: chain(),
        base_fee: 10,
        sender: &info,
    };
    let validated = validate_transaction(&tx, &ctx).unwrap();
    assert_eq!(validated.bootstrap_public_key, None);

    apply_bootstrap(&mut state, &validated).unwrap();

    // Aucune mutation d'état.
    assert_eq!(state.native_state_root(), root_before);
}

#[test]
fn bootstrap_after_genesis_credit() {
    // Simule un compte crédité par une allocation Genesis : l'utilisateur
    // active ensuite sa clé via une transaction.
    let kp = NativeKeypair::from_seed([0x99; 32]);
    let pk = kp.public_key();
    let sender = derive_native_address(&pk);

    let mut state = NativeState::new();
    state
        .credit(sender, Amount::from_base_units(10_000_000))
        .unwrap();

    let tx = signed_bootstrap_transfer(&kp, 0, 1_000, 20);
    let info = sender_info_from_state(&state, &sender);
    let ctx = ValidationContext {
        expected_chain_id: chain(),
        base_fee: 10,
        sender: &info,
    };
    let validated = validate_transaction(&tx, &ctx).unwrap();

    assert_eq!(validated.bootstrap_public_key, Some(pk));
    apply_bootstrap(&mut state, &validated).unwrap();

    assert_eq!(state.public_key_of(&sender), Some(pk));
}

#[test]
fn bootstrap_root_is_order_independent() {
    // Deux comptes crédités dans un ordre différent puis activés dans un
    // ordre différent → même native_state_root.
    let kp1 = NativeKeypair::from_seed([0x01; 32]);
    let kp2 = NativeKeypair::from_seed([0x02; 32]);
    let s1 = derive_native_address(&kp1.public_key());
    let s2 = derive_native_address(&kp2.public_key());

    let mut a = NativeState::new();
    a.credit(s1, Amount::from_base_units(100)).unwrap();
    a.credit(s2, Amount::from_base_units(200)).unwrap();
    a.set_public_key(s1, kp1.public_key()).unwrap();
    a.set_public_key(s2, kp2.public_key()).unwrap();

    let mut b = NativeState::new();
    b.credit(s2, Amount::from_base_units(200)).unwrap();
    b.credit(s1, Amount::from_base_units(100)).unwrap();
    b.set_public_key(s2, kp2.public_key()).unwrap();
    b.set_public_key(s1, kp1.public_key()).unwrap();

    assert_eq!(a.native_state_root(), b.native_state_root());
}
