//! Application des transactions natives au state.
//!
//! ## Mutations d'une transaction
//!
//! 1. débite l'émetteur de `value + total_fee` ;
//! 2. incrémente son nonce ;
//! 3. enregistre sa clé publique si bootstrap ;
//! 4. crédite le destinataire de `value` ;
//! 5. crédite le validateur de `validator_fee = 90 %` ;
//! 6. `burn_fee = 10 %` est **brûlé** — implicitement, en n'étant crédité
//!    à personne.
//!
//! ## Atomicité
//!
//! Toutes les mutations d'une transaction sont atomiques. De même pour un
//! bloc entier via [`apply_block_transfers`].
//!
//! ## TODO (V1 complète)
//!
//! L'implémentation actuelle utilise `NativeState::clone` pour garantir
//! l'atomicité. Acceptable pour la V1 initiale ; à remplacer par un undo
//! log pour les grandes bases d'état.

use sango_crypto::derive_native_address;
use sango_primitives::{Amount, Hash32, NativeAddress, PublicKey};
use sango_state::{NativeState, StateError};
use sango_tx::{split_fee, ValidatedTransaction};
use sango_types::{Transaction, TxKind};

use crate::error::ApplyError;

/// Gas consommé par un transfert natif simple.
///
/// Constante normative V1 : tout `TX_TRANSFER` consomme exactement ce
/// montant de gas.
pub const NATIVE_TRANSFER_GAS: u64 = 21_000;

/// Détail de l'application d'une transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppliedTransaction {
    /// Hash canonique de la transaction.
    pub tx_hash: Hash32,
    /// Adresse native de l'émetteur.
    pub sender: NativeAddress,
    /// Adresse native du destinataire.
    pub recipient: NativeAddress,
    /// Montant transféré (base units).
    pub value: u128,
    /// Gas consommé.
    pub gas_used: u64,
    /// Prix effectif par unité de gas.
    pub effective_gas_price: u128,
    /// `gas_used * effective_gas_price`.
    pub total_fee: u128,
    /// Part validateur (`90 %`).
    pub validator_fee: u128,
    /// Part brûlée (`10 %`).
    pub burn_fee: u128,
    /// Clé publique enregistrée lors d'un bootstrap, si applicable.
    pub bootstrap_public_key: Option<PublicKey>,
}

/// Résultat de l'application d'un bloc entier.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BlockApplyResult {
    /// Transactions appliquées, dans l'ordre du bloc.
    pub applied: Vec<AppliedTransaction>,
    /// Somme des gas consommés.
    pub total_gas_used: u64,
    /// Somme des frais totaux.
    pub total_fee: u128,
    /// Somme des parts validateurs.
    pub total_validator_fee: u128,
    /// Somme des parts brûlées.
    pub total_burned: u128,
}

/// Applique un transfert natif avec le gas standard.
pub fn apply_transfer(
    state: &mut NativeState,
    tx: &Transaction,
    validated: &ValidatedTransaction,
    fee_recipient: NativeAddress,
) -> Result<AppliedTransaction, ApplyError> {
    apply_transfer_with_gas(state, tx, validated, NATIVE_TRANSFER_GAS, fee_recipient)
}

/// Applique un transfert natif avec un `gas_used` explicite.
///
/// **Atomique** : en cas d'échec, `state` est inchangé.
pub fn apply_transfer_with_gas(
    state: &mut NativeState,
    tx: &Transaction,
    validated: &ValidatedTransaction,
    gas_used: u64,
    fee_recipient: NativeAddress,
) -> Result<AppliedTransaction, ApplyError> {
    let snapshot = state.clone();
    match apply_transfer_no_rollback(state, tx, validated, gas_used, fee_recipient) {
        Ok(r) => Ok(r),
        Err(e) => {
            *state = snapshot;
            Err(e)
        }
    }
}

/// Applique une séquence de transferts natifs **atomiquement**.
///
/// Si **une seule** transaction échoue, tout le bloc est annulé : `state`
/// est restauré dans son état initial.
pub fn apply_block_transfers(
    state: &mut NativeState,
    txs: &[Transaction],
    validated: &[ValidatedTransaction],
    fee_recipient: NativeAddress,
) -> Result<BlockApplyResult, ApplyError> {
    if txs.len() != validated.len() {
        return Err(ApplyError::LengthMismatch {
            txs: txs.len(),
            validated: validated.len(),
        });
    }

    let snapshot = state.clone();
    let mut result = BlockApplyResult::default();

    for (tx, v) in txs.iter().zip(validated.iter()) {
        match apply_transfer_no_rollback(state, tx, v, NATIVE_TRANSFER_GAS, fee_recipient) {
            Ok(applied) => {
                result.total_gas_used = result.total_gas_used.saturating_add(applied.gas_used);
                result.total_fee = result.total_fee.saturating_add(applied.total_fee);
                result.total_validator_fee = result
                    .total_validator_fee
                    .saturating_add(applied.validator_fee);
                result.total_burned = result.total_burned.saturating_add(applied.burn_fee);
                result.applied.push(applied);
            }
            Err(e) => {
                *state = snapshot;
                return Err(e);
            }
        }
    }

    Ok(result)
}

/// Implémentation sans rollback.
///
/// Suppose que l'appelant a snapshoté l'état et le restaurera en cas
/// d'erreur.
fn apply_transfer_no_rollback(
    state: &mut NativeState,
    tx: &Transaction,
    validated: &ValidatedTransaction,
    gas_used: u64,
    fee_recipient: NativeAddress,
) -> Result<AppliedTransaction, ApplyError> {
    // (1) Structure.
    if tx.tx_kind != TxKind::Transfer {
        return Err(ApplyError::UnsupportedTxKind(tx.tx_kind));
    }
    let recipient = tx.recipient.ok_or(ApplyError::MissingRecipient)?;

    // (2) Montants.
    let sender = validated.sender;
    let value = validated.value;
    let effective_price = validated.effective_gas_price;

    let total_fee = (gas_used as u128)
        .checked_mul(effective_price)
        .ok_or(ApplyError::TotalFeeOverflow)?;
    let (validator_fee, burn_fee) = split_fee(total_fee);

    let debit_total = value
        .checked_add(total_fee)
        .ok_or(ApplyError::FeeOverflow {
            value,
            fee: total_fee,
        })?;

    // (3) Vérifications préalables — rendent les mutations infaillibles.
    let sender_balance = state.balance_of(&sender).base_units();
    if sender_balance < debit_total {
        return Err(ApplyError::InsufficientBalance {
            needed: debit_total,
            available: sender_balance,
        });
    }

    if state.nonce_of(&sender) == u64::MAX {
        return Err(ApplyError::NonceOverflow { address: sender });
    }

    if recipient != sender {
        let rec_bal = state.balance_of(&recipient).base_units();
        rec_bal
            .checked_add(value)
            .ok_or(ApplyError::BalanceOverflow { address: recipient })?;
    }

    if fee_recipient != sender && fee_recipient != recipient {
        let fee_bal = state.balance_of(&fee_recipient).base_units();
        fee_bal
            .checked_add(validator_fee)
            .ok_or(ApplyError::BalanceOverflow {
                address: fee_recipient,
            })?;
    }

    if let Some(pk) = validated.bootstrap_public_key {
        if pk.is_zero() {
            return Err(ApplyError::State(StateError::PublicKeyIsZero));
        }
        if derive_native_address(&pk) != sender {
            return Err(ApplyError::State(
                StateError::PublicKeyDoesNotMatchAddress { address: sender },
            ));
        }
        if state.public_key_of(&sender).is_some() {
            return Err(ApplyError::State(StateError::PublicKeyAlreadyRegistered {
                address: sender,
            }));
        }
    }

    // (4) Mutations — infaillibles après les vérifications ci-dessus.
    state
        .debit(sender, Amount::from_base_units(debit_total))
        .map_err(map_state_error)?;
    state.bump_nonce(sender).map_err(map_state_error)?;
    if let Some(pk) = validated.bootstrap_public_key {
        state.set_public_key(sender, pk).map_err(map_state_error)?;
    }
    state
        .credit(recipient, Amount::from_base_units(value))
        .map_err(map_state_error)?;
    state
        .credit(fee_recipient, Amount::from_base_units(validator_fee))
        .map_err(map_state_error)?;

    Ok(AppliedTransaction {
        tx_hash: validated.tx_hash,
        sender,
        recipient,
        value,
        gas_used,
        effective_gas_price: effective_price,
        total_fee,
        validator_fee,
        burn_fee,
        bootstrap_public_key: validated.bootstrap_public_key,
    })
}

fn map_state_error(e: StateError) -> ApplyError {
    match e {
        StateError::InsufficientBalance {
            requested,
            available,
            ..
        } => ApplyError::InsufficientBalance {
            needed: requested,
            available,
        },
        StateError::BalanceOverflow { address } => ApplyError::BalanceOverflow { address },
        StateError::NonceOverflow { address } => ApplyError::NonceOverflow { address },
        other => ApplyError::State(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sango_crypto::{derive_native_address, NativeKeypair};
    use sango_primitives::{Amount, ChainId32, Signature};
    use sango_state::NativeState;
    use sango_tx::{validate_transaction, SenderInfo, TxValidationError, ValidationContext};
    use sango_types::{NativeAccount, Transaction, TxKind};

    fn chain() -> ChainId32 {
        ChainId32::from_bytes([0x11; 32])
    }

    fn validator() -> NativeAddress {
        NativeAddress::from_bytes([0xef; 20])
    }

    fn recipient() -> NativeAddress {
        NativeAddress::from_bytes([0xbb; 20])
    }

    fn bootstrap_tx(kp: &NativeKeypair, nonce: u64, value: u128) -> Transaction {
        let pk = kp.public_key();
        let sender = derive_native_address(&pk);
        let tx = Transaction {
            version: 1,
            chain_id: chain(),
            nonce,
            sender,
            public_key: Some(pk),
            gas_limit: NATIVE_TRANSFER_GAS,
            max_fee: 20,
            priority_fee: 2,
            value: Amount::from_base_units(value),
            tx_kind: TxKind::Transfer,
            recipient: Some(recipient()),
            data: Vec::new(),
            signature: Signature::ZERO,
        };
        tx.sign(kp)
    }

    fn validate(
        state: &NativeState,
        tx: &Transaction,
    ) -> Result<ValidatedTransaction, TxValidationError> {
        let addr = tx.sender;
        let info = match state.get_account(&addr) {
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
            None => SenderInfo::ghost(addr, 0, 0),
        };
        let ctx = ValidationContext {
            expected_chain_id: chain(),
            base_fee: 10,
            sender: &info,
        };
        validate_transaction(tx, &ctx)
    }

    #[test]
    fn apply_transfer_moves_funds_and_splits_fee() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let pk = kp.public_key();
        let sender = derive_native_address(&pk);

        let mut state = NativeState::new();
        state
            .credit(sender, Amount::from_base_units(1_000_000))
            .unwrap();

        let tx = bootstrap_tx(&kp, 0, 100);
        let v = validate(&state, &tx).unwrap();
        let applied = apply_transfer(&mut state, &tx, &v, validator()).unwrap();

        // total_fee = 21_000 × 12 = 252_000 ; validator = 226_800 ; burn = 25_200
        assert_eq!(applied.total_fee, 252_000);
        assert_eq!(applied.validator_fee, 226_800);
        assert_eq!(applied.burn_fee, 25_200);

        assert_eq!(
            state.balance_of(&sender),
            Amount::from_base_units(1_000_000 - 100 - 252_000)
        );
        assert_eq!(state.balance_of(&recipient()), Amount::from_base_units(100));
        assert_eq!(
            state.balance_of(&validator()),
            Amount::from_base_units(226_800)
        );
        assert_eq!(state.nonce_of(&sender), 1);
        assert_eq!(state.public_key_of(&sender), Some(pk));
    }

    #[test]
    fn apply_transfer_self_is_net_fee_only() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let pk = kp.public_key();
        let sender = derive_native_address(&pk);

        let mut state = NativeState::new();
        state.set_account(NativeAccount::from_public_key(
            pk,
            Amount::from_base_units(1_000_000),
            0,
        ));

        let mut tx = bootstrap_tx(&kp, 0, 100);
        tx.recipient = Some(sender);
        let tx = tx.sign(&kp);
        let v = validate(&state, &tx).unwrap();
        let applied = apply_transfer(&mut state, &tx, &v, validator()).unwrap();

        assert_eq!(applied.total_fee, 252_000);
        // Self-transfer : net -252_000
        assert_eq!(
            state.balance_of(&sender),
            Amount::from_base_units(1_000_000 - 252_000)
        );
        assert_eq!(state.nonce_of(&sender), 1);
    }

    #[test]
    fn apply_transfer_sender_is_fee_recipient() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let pk = kp.public_key();
        let sender = derive_native_address(&pk);

        let mut state = NativeState::new();
        state.set_account(NativeAccount::from_public_key(
            pk,
            Amount::from_base_units(1_000_000),
            0,
        ));

        let tx = bootstrap_tx(&kp, 0, 100);
        let v = validate(&state, &tx).unwrap();
        let applied = apply_transfer(&mut state, &tx, &v, sender).unwrap();

        // Sender = fee_recipient :
        //   -value      = -100
        //   -total_fee  = -252_000
        //   +validator  = +226_800
        //   net         = -25_300
        assert_eq!(
            state.balance_of(&sender),
            Amount::from_base_units(1_000_000 - 25_300)
        );
        assert_eq!(applied.burn_fee, 25_200);
    }

    #[test]
    fn apply_transfer_rejects_insufficient_balance_and_rolls_back() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let pk = kp.public_key();
        let sender = derive_native_address(&pk);

        let mut state = NativeState::new();
        state.set_account(NativeAccount::from_public_key(
            pk,
            Amount::from_base_units(1_000_000),
            0,
        ));

        let tx = bootstrap_tx(&kp, 0, 100);
        let v = validate(&state, &tx).unwrap();

        // Vider le solde après validation.
        state.set_account(NativeAccount::from_public_key(pk, Amount::ZERO, 0));

        let err = apply_transfer(&mut state, &tx, &v, validator()).unwrap_err();
        assert!(matches!(err, ApplyError::InsufficientBalance { .. }));
        // Rollback : état inchangé.
        assert_eq!(state.balance_of(&sender), Amount::ZERO);
        assert_eq!(state.nonce_of(&sender), 0);
    }

    #[test]
    fn apply_transfer_rejects_wrong_tx_kind() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let pk = kp.public_key();
        let sender = derive_native_address(&pk);

        let mut state = NativeState::new();
        state
            .credit(sender, Amount::from_base_units(1_000_000))
            .unwrap();

        let tx = bootstrap_tx(&kp, 0, 100);
        let v = validate(&state, &tx).unwrap();

        let mut tx_call = tx;
        tx_call.tx_kind = TxKind::ContractCall;
        let err = apply_transfer(&mut state, &tx_call, &v, validator()).unwrap_err();
        assert_eq!(err, ApplyError::UnsupportedTxKind(TxKind::ContractCall));
    }

    #[test]
    fn apply_block_multiple_transfers() {
        let kp1 = NativeKeypair::from_seed([0x01; 32]);
        let kp2 = NativeKeypair::from_seed([0x02; 32]);
        let s1 = derive_native_address(&kp1.public_key());
        let s2 = derive_native_address(&kp2.public_key());

        let mut state = NativeState::new();
        state
            .credit(s1, Amount::from_base_units(1_000_000))
            .unwrap();
        state
            .credit(s2, Amount::from_base_units(1_000_000))
            .unwrap();

        let tx1 = bootstrap_tx(&kp1, 0, 100);
        let tx2 = bootstrap_tx(&kp2, 0, 200);

        let v1 = validate(&state, &tx1).unwrap();
        let v2 = validate(&state, &tx2).unwrap();

        let result =
            apply_block_transfers(&mut state, &[tx1, tx2], &[v1, v2], validator()).unwrap();

        assert_eq!(result.applied.len(), 2);
        assert_eq!(result.total_fee, 2 * 252_000);
        assert_eq!(result.total_validator_fee, 2 * 226_800);
        assert_eq!(result.total_burned, 2 * 25_200);
        assert_eq!(state.nonce_of(&s1), 1);
        assert_eq!(state.nonce_of(&s2), 1);
    }

    #[test]
    fn apply_block_is_atomic_on_failure() {
        let kp1 = NativeKeypair::from_seed([0x01; 32]);
        let kp2 = NativeKeypair::from_seed([0x02; 32]);
        let s2 = derive_native_address(&kp2.public_key());

        let mut state = NativeState::new();
        let s1 = derive_native_address(&kp1.public_key());
        state
            .credit(s1, Amount::from_base_units(1_000_000))
            .unwrap();
        state
            .credit(s2, Amount::from_base_units(1_000_000))
            .unwrap();

        let tx1 = bootstrap_tx(&kp1, 0, 100);
        let tx2 = bootstrap_tx(&kp2, 0, 200);
        let v1 = validate(&state, &tx1).unwrap();
        let v2 = validate(&state, &tx2).unwrap();

        // Casser le solde de s2 après validation.
        state.set_account(NativeAccount::from_public_key(
            kp2.public_key(),
            Amount::ZERO,
            0,
        ));
        let root_before = state.native_state_root();

        let err =
            apply_block_transfers(&mut state, &[tx1, tx2], &[v1, v2], validator()).unwrap_err();
        assert!(matches!(err, ApplyError::InsufficientBalance { .. }));
        // Rollback complet : tx1 non appliquée.
        assert_eq!(state.native_state_root(), root_before);
        assert_eq!(state.nonce_of(&s1), 0);
        assert_eq!(state.nonce_of(&s2), 0);
    }

    #[test]
    fn apply_block_length_mismatch() {
        let mut state = NativeState::new();
        let r = apply_block_transfers(&mut state, &[], &[], validator()).unwrap();
        assert!(r.applied.is_empty());

        let kp = NativeKeypair::from_seed([0x42; 32]);
        let tx = bootstrap_tx(&kp, 0, 1);
        let err = apply_block_transfers(&mut state, &[tx], &[], validator()).unwrap_err();
        assert_eq!(
            err,
            ApplyError::LengthMismatch {
                txs: 1,
                validated: 0
            }
        );
    }
}
