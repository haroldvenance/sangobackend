//! Application des transactions de staking natif.
//!
//! Freeze sections 13, 46-50.

use sango_primitives::{Amount, NativeAddress};
use sango_state::NativeState;
use sango_tx::ValidatedTransaction;
use sango_types::{staking_params, Delegation, Transaction, TxKind, ValidatorInfo};

use crate::apply::AppliedTransaction;
use crate::error::ApplyError;
use crate::ExecutionContext;

/// Gas consommé par chaque opération de staking.
#[must_use]
pub fn gas_for(kind: TxKind) -> Option<u64> {
    match kind {
        TxKind::Bond => Some(50_000),
        TxKind::Unbond => Some(50_000),
        TxKind::Delegate => Some(80_000),
        TxKind::Undelegate => Some(80_000),
        TxKind::ClaimRewards => Some(40_000),
        TxKind::RegisterValidator => Some(200_000),
        TxKind::UpdateCommission => Some(30_000),
        TxKind::Unjail => Some(30_000),
        _ => None,
    }
}

/// Applique une transaction de staking sans rollback.
///
/// Suppose que l'appelant a snapshoté l'état et le restaurera en cas
/// d'erreur. Met à jour `state` en place.
pub fn apply_staking_no_rollback(
    state: &mut NativeState,
    tx: &Transaction,
    validated: &ValidatedTransaction,
    gas_used: u64,
    ctx: &ExecutionContext,
) -> Result<AppliedTransaction, ApplyError> {
    let sender = validated.sender;
    let value = Amount::from_base_units(validated.value);
    let effective_price = validated.effective_gas_price;

    let total_fee = (gas_used as u128)
        .checked_mul(effective_price)
        .ok_or(ApplyError::TotalFeeOverflow)?;
    let (validator_fee, burn_fee) = sango_tx::split_fee(total_fee);

    // (0) Bootstrap éventuel : activer la clé publique avant toute
    // autre opération, pour que l'état reflète le sender correctement.
    if let Some(pk) = validated.bootstrap_public_key {
        state
            .set_public_key(sender, pk)
            .map_err(ApplyError::State)?;
    }

    // (1) Vérifier que le compte a bien une clé publique enregistrée.
    let account = state
        .get_account(&sender)
        .ok_or(ApplyError::MissingPublicKey)?;
    if !account.has_registered_public_key() {
        return Err(ApplyError::MissingPublicKey);
    }
    let account_public_key = account.public_key;

    // (2) Dispatcher sur l'opération.
    match tx.tx_kind {
        TxKind::Bond => apply_bond(state, sender, value, total_fee, ctx)?,
        TxKind::Unbond => apply_unbond(state, sender, value, total_fee, ctx)?,
        TxKind::Delegate => {
            let recipient = tx.recipient.ok_or(ApplyError::MissingRecipient)?;
            apply_delegate(state, sender, recipient, value, total_fee)?;
        }
        TxKind::Undelegate => {
            let recipient = tx.recipient.ok_or(ApplyError::MissingRecipient)?;
            apply_undelegate(state, sender, recipient, value, total_fee, ctx)?;
        }
        TxKind::ClaimRewards => {
            let recipient = tx.recipient.ok_or(ApplyError::MissingRecipient)?;
            apply_claim_rewards(state, sender, recipient, total_fee)?;
        }
        TxKind::RegisterValidator => {
            apply_register_validator(
                state,
                sender,
                account_public_key,
                value,
                total_fee,
                tx.data.as_slice(),
            )?;
        }
        TxKind::UpdateCommission => {
            apply_update_commission(state, sender, total_fee, tx.data.as_slice(), ctx)?;
        }
        TxKind::Unjail => apply_unjail(state, sender, total_fee, ctx)?,
        other => return Err(ApplyError::UnsupportedTxKind(other)),
    }

    // (3) Paiement des frais au validator courant.
    state
        .credit(ctx.fee_recipient, Amount::from_base_units(validator_fee))
        .map_err(map_state_error)?;

    // (4) Nonce.
    state.bump_nonce(sender).map_err(map_state_error)?;

    let recipient_for_log = match tx.tx_kind {
        TxKind::Delegate | TxKind::Undelegate | TxKind::ClaimRewards => {
            tx.recipient.unwrap_or(sender)
        }
        _ => sender,
    };

    Ok(AppliedTransaction {
        tx_hash: validated.tx_hash,
        sender,
        recipient: recipient_for_log,
        value: value.base_units(),
        gas_used,
        effective_gas_price: effective_price,
        total_fee,
        validator_fee,
        burn_fee,
        bootstrap_public_key: validated.bootstrap_public_key,
    })
}

// --- Opérations individuelles ----------------------------------------------

fn apply_bond(
    state: &mut NativeState,
    sender: NativeAddress,
    value: Amount,
    total_fee: u128,
    _ctx: &ExecutionContext,
) -> Result<(), ApplyError> {
    let mut info = state
        .get_validator(&sender)
        .ok_or(ApplyError::NotAValidator(sender))?;

    let debit = value.base_units().saturating_add(total_fee);
    check_sender_balance(state, sender, debit)?;

    // Débiter le compte, ajouter au self-stake.
    state
        .debit(sender, Amount::from_base_units(debit))
        .map_err(map_state_error)?;
    info.self_stake = info
        .self_stake
        .checked_add(value)
        .ok_or(ApplyError::TotalFeeOverflow)?;
    state.set_validator(info);
    Ok(())
}

fn apply_unbond(
    state: &mut NativeState,
    sender: NativeAddress,
    value: Amount,
    total_fee: u128,
    ctx: &ExecutionContext,
) -> Result<(), ApplyError> {
    let mut info = state
        .get_validator(&sender)
        .ok_or(ApplyError::NotAValidator(sender))?;

    let available = info.self_stake.base_units();
    let requested = value.base_units();
    if available < requested {
        return Err(ApplyError::InsufficientSelfStakeAvailable {
            needed: requested,
            available,
        });
    }

    let remaining = available - requested;
    let min = staking_params::min_self_stake().base_units();
    if remaining < min {
        return Err(ApplyError::InsufficientSelfStake {
            needed: min,
            would_be: remaining,
        });
    }

    check_sender_balance(state, sender, total_fee)?;

    // Retirer du self-stake.
    info.self_stake = Amount::from_base_units(remaining);
    state.set_validator(info);

    // Ajouter à la file d'unbonding via `Delegation(sender, sender)`.
    let mut unbond = state
        .get_delegation(&sender, &sender)
        .unwrap_or_else(|| Delegation::empty(sender, sender));
    unbond.unbonding = unbond
        .unbonding
        .checked_add(value)
        .ok_or(ApplyError::TotalFeeOverflow)?;
    unbond.unbonding_until = Some(
        ctx.current_time
            .saturating_add(staking_params::UNBONDING_PERIOD_SECS),
    );
    state.set_delegation(unbond);

    // Frais.
    state
        .debit(sender, Amount::from_base_units(total_fee))
        .map_err(map_state_error)?;
    Ok(())
}

fn apply_delegate(
    state: &mut NativeState,
    sender: NativeAddress,
    validator: NativeAddress,
    value: Amount,
    total_fee: u128,
) -> Result<(), ApplyError> {
    if sender == validator {
        return Err(ApplyError::SelfDelegation);
    }

    let mut info = state
        .get_validator(&validator)
        .ok_or(ApplyError::ValidatorNotFound(validator))?;
    if !info.is_active() {
        return Err(ApplyError::ValidatorNotFound(validator));
    }

    let debit = value.base_units().saturating_add(total_fee);
    check_sender_balance(state, sender, debit)?;

    state
        .debit(sender, Amount::from_base_units(debit))
        .map_err(map_state_error)?;

    let mut d = state
        .get_delegation(&sender, &validator)
        .unwrap_or_else(|| Delegation::empty(sender, validator));
    d.bonded = d
        .bonded
        .checked_add(value)
        .ok_or(ApplyError::TotalFeeOverflow)?;
    state.set_delegation(d);

    info.total_delegated = info
        .total_delegated
        .checked_add(value)
        .ok_or(ApplyError::TotalFeeOverflow)?;
    state.set_validator(info);
    Ok(())
}

fn apply_undelegate(
    state: &mut NativeState,
    sender: NativeAddress,
    validator: NativeAddress,
    value: Amount,
    total_fee: u128,
    ctx: &ExecutionContext,
) -> Result<(), ApplyError> {
    let mut d =
        state
            .get_delegation(&sender, &validator)
            .ok_or(ApplyError::InsufficientDelegation {
                needed: value.base_units(),
                available: 0,
            })?;

    let available = d.bonded.base_units();
    let requested = value.base_units();
    if available < requested {
        return Err(ApplyError::InsufficientDelegation {
            needed: requested,
            available,
        });
    }

    check_sender_balance(state, sender, total_fee)?;

    d.bonded = Amount::from_base_units(available - requested);
    d.unbonding = d
        .unbonding
        .checked_add(value)
        .ok_or(ApplyError::TotalFeeOverflow)?;
    d.unbonding_until = Some(
        ctx.current_time
            .saturating_add(staking_params::UNBONDING_PERIOD_SECS),
    );

    if d.is_empty() {
        state.remove_delegation(&sender, &validator);
    } else {
        state.set_delegation(d);
    }

    // Mettre à jour le total délégué du validator.
    if let Some(mut info) = state.get_validator(&validator) {
        info.total_delegated = info
            .total_delegated
            .checked_sub(value)
            .unwrap_or(Amount::ZERO);
        state.set_validator(info);
    }

    state
        .debit(sender, Amount::from_base_units(total_fee))
        .map_err(map_state_error)?;
    Ok(())
}

fn apply_claim_rewards(
    state: &mut NativeState,
    sender: NativeAddress,
    validator: NativeAddress,
    total_fee: u128,
) -> Result<(), ApplyError> {
    let mut d =
        state
            .get_delegation(&sender, &validator)
            .ok_or(ApplyError::InsufficientDelegation {
                needed: 0,
                available: 0,
            })?;

    check_sender_balance(state, sender, total_fee)?;

    let rewards = d.pending_rewards;
    d.pending_rewards = Amount::ZERO;
    if d.is_empty() {
        state.remove_delegation(&sender, &validator);
    } else {
        state.set_delegation(d);
    }

    state.credit(sender, rewards).map_err(map_state_error)?;
    state
        .debit(sender, Amount::from_base_units(total_fee))
        .map_err(map_state_error)?;
    Ok(())
}

fn apply_register_validator(
    state: &mut NativeState,
    sender: NativeAddress,
    public_key: sango_primitives::PublicKey,
    self_stake: Amount,
    total_fee: u128,
    data: &[u8],
) -> Result<(), ApplyError> {
    if state.validator_exists(&sender) {
        return Err(ApplyError::ValidatorAlreadyExists(sender));
    }
    if data.len() != 4 {
        return Err(ApplyError::InvalidCommissionData);
    }
    let commission_bps = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if commission_bps > staking_params::MAX_COMMISSION_BPS {
        return Err(ApplyError::CommissionTooHigh {
            got: commission_bps,
            max: staking_params::MAX_COMMISSION_BPS,
        });
    }

    let debit = self_stake.base_units().saturating_add(total_fee);
    check_sender_balance(state, sender, debit)?;

    state
        .debit(sender, Amount::from_base_units(debit))
        .map_err(map_state_error)?;

    state.set_validator(ValidatorInfo {
        address: sender,
        public_key,
        self_stake,
        total_delegated: Amount::ZERO,
        commission_bps,
        pending_commission_bps: None,
        pending_commission_at: None,
        jailed: false,
        jailed_until: None,
        downtime_window_start: 0,
        downtime_missed: 0,
    });
    Ok(())
}

fn apply_update_commission(
    state: &mut NativeState,
    sender: NativeAddress,
    total_fee: u128,
    data: &[u8],
    ctx: &ExecutionContext,
) -> Result<(), ApplyError> {
    let mut info = state
        .get_validator(&sender)
        .ok_or(ApplyError::NotAValidator(sender))?;

    if data.len() != 4 {
        return Err(ApplyError::InvalidCommissionData);
    }
    let new_bps = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if new_bps > staking_params::MAX_COMMISSION_BPS {
        return Err(ApplyError::CommissionTooHigh {
            got: new_bps,
            max: staking_params::MAX_COMMISSION_BPS,
        });
    }

    check_sender_balance(state, sender, total_fee)?;

    info.pending_commission_bps = Some(new_bps);
    info.pending_commission_at = Some(
        ctx.current_time
            .saturating_add(staking_params::COMMISSION_UPDATE_DELAY_SECS),
    );
    state.set_validator(info);

    state
        .debit(sender, Amount::from_base_units(total_fee))
        .map_err(map_state_error)?;
    Ok(())
}

fn apply_unjail(
    state: &mut NativeState,
    sender: NativeAddress,
    total_fee: u128,
    ctx: &ExecutionContext,
) -> Result<(), ApplyError> {
    let mut info = state
        .get_validator(&sender)
        .ok_or(ApplyError::NotAValidator(sender))?;

    if !info.jailed {
        return Err(ApplyError::NotJailed(sender));
    }
    if let Some(until) = info.jailed_until {
        if ctx.current_time < until {
            return Err(ApplyError::JailNotExpired {
                until,
                now: ctx.current_time,
            });
        }
    }

    check_sender_balance(state, sender, total_fee)?;

    info.jailed = false;
    info.jailed_until = None;
    state.set_validator(info);

    state
        .debit(sender, Amount::from_base_units(total_fee))
        .map_err(map_state_error)?;
    Ok(())
}

// --- Helpers ----------------------------------------------------------------

fn check_sender_balance(
    state: &NativeState,
    sender: NativeAddress,
    needed: u128,
) -> Result<(), ApplyError> {
    let available = state.balance_of(&sender).base_units();
    if available < needed {
        return Err(ApplyError::InsufficientBalance { needed, available });
    }
    Ok(())
}

fn map_state_error(e: sango_state::StateError) -> ApplyError {
    match e {
        sango_state::StateError::InsufficientBalance {
            requested,
            available,
            ..
        } => ApplyError::InsufficientBalance {
            needed: requested,
            available,
        },
        sango_state::StateError::BalanceOverflow { address } => {
            ApplyError::BalanceOverflow { address }
        }
        sango_state::StateError::NonceOverflow { address } => ApplyError::NonceOverflow { address },
        other => ApplyError::State(other),
    }
}

// --- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sango_crypto::{derive_native_address, NativeKeypair};
    use sango_primitives::{ChainId32, Signature};
    use sango_state::NativeState;
    use sango_tx::{validate_transaction, SenderInfo, TxValidationError, ValidationContext};
    use sango_types::NativeAccount;

    fn chain() -> ChainId32 {
        ChainId32::from_bytes([0x11; 32])
    }

    fn now() -> u64 {
        1_700_000_000
    }

    fn exec_ctx(fee_recipient: NativeAddress) -> ExecutionContext {
        ExecutionContext {
            chain_id: chain(),
            base_fee: 10,
            fee_recipient,
            initial_supply: Amount::from_sango(1_000_000_000).unwrap(),
            current_time: now(),
            current_height: 0,
            rewards_enabled: false,
        }
    }

    fn fee_recipient() -> NativeAddress {
        NativeAddress::from_bytes([0xef; 20])
    }

    /// Crée un compte actif (avec pubkey) financé.
    fn funded_account(
        state: &mut NativeState,
        kp: &NativeKeypair,
        balance_sango: u128,
    ) -> NativeAddress {
        let pk = kp.public_key();
        let address = derive_native_address(&pk);
        state.set_account(NativeAccount::from_public_key(
            pk,
            Amount::from_sango(balance_sango).unwrap(),
            0,
        ));
        address
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

    fn sign_tx(kp: &NativeKeypair, mut tx: Transaction) -> Transaction {
        tx.public_key = None;
        tx.signature = Signature::ZERO;
        tx.sign(kp)
    }

    // --- RegisterValidator --------------------------------------------------

    #[test]
    fn register_validator_happy_path() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let mut state = NativeState::new();
        let addr = funded_account(&mut state, &kp, 200_000);

        let data = 700u32.to_be_bytes().to_vec();
        let tx = sign_tx(
            &kp,
            Transaction {
                version: 1,
                chain_id: chain(),
                nonce: 0,
                sender: addr,
                public_key: None,
                gas_limit: 200_000,
                max_fee: 20,
                priority_fee: 2,
                value: Amount::from_sango(100_000).unwrap(),
                tx_kind: TxKind::RegisterValidator,
                recipient: None,
                data,
                signature: Signature::ZERO,
            },
        );

        let v = validate(&state, &tx).unwrap();
        let ctx = exec_ctx(fee_recipient());
        apply_staking_no_rollback(&mut state, &tx, &v, 200_000, &ctx).unwrap();

        let info = state.get_validator(&addr).unwrap();
        assert_eq!(info.self_stake, Amount::from_sango(100_000).unwrap());
        assert_eq!(info.commission_bps, 700);
        assert!(!info.jailed);
        // Solde débité de 100 000 SANGO + fees.
        let total_fee = 200_000u128 * 12;
        assert_eq!(
            state.balance_of(&addr).base_units(),
            Amount::from_sango(100_000).unwrap().base_units() - total_fee
        );
    }

    #[test]
    fn register_validator_twice_fails() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let mut state = NativeState::new();
        let addr = funded_account(&mut state, &kp, 300_000);

        let data = 700u32.to_be_bytes().to_vec();
        let tx1 = sign_tx(
            &kp,
            Transaction {
                version: 1,
                chain_id: chain(),
                nonce: 0,
                sender: addr,
                public_key: None,
                gas_limit: 200_000,
                max_fee: 20,
                priority_fee: 2,
                value: Amount::from_sango(100_000).unwrap(),
                tx_kind: TxKind::RegisterValidator,
                recipient: None,
                data: data.clone(),
                signature: Signature::ZERO,
            },
        );
        let v1 = validate(&state, &tx1).unwrap();
        apply_staking_no_rollback(&mut state, &tx1, &v1, 200_000, &exec_ctx(fee_recipient()))
            .unwrap();

        let tx2 = sign_tx(
            &kp,
            Transaction {
                version: 1,
                chain_id: chain(),
                nonce: 1,
                sender: addr,
                public_key: None,
                gas_limit: 200_000,
                max_fee: 20,
                priority_fee: 2,
                value: Amount::from_sango(100_000).unwrap(),
                tx_kind: TxKind::RegisterValidator,
                recipient: None,
                data,
                signature: Signature::ZERO,
            },
        );
        let v2 = validate(&state, &tx2).unwrap();
        let err =
            apply_staking_no_rollback(&mut state, &tx2, &v2, 200_000, &exec_ctx(fee_recipient()))
                .unwrap_err();
        assert!(matches!(err, ApplyError::ValidatorAlreadyExists(_)));
    }

    // --- Bond / Unbond ------------------------------------------------------

    #[test]
    fn bond_tops_up_self_stake() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let mut state = NativeState::new();
        let addr = funded_account(&mut state, &kp, 500_000);

        // Enregistrer d'abord.
        state.set_validator(ValidatorInfo {
            address: addr,
            public_key: kp.public_key(),
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

        let tx = sign_tx(
            &kp,
            Transaction {
                version: 1,
                chain_id: chain(),
                nonce: 0,
                sender: addr,
                public_key: None,
                gas_limit: 50_000,
                max_fee: 20,
                priority_fee: 2,
                value: Amount::from_sango(50_000).unwrap(),
                tx_kind: TxKind::Bond,
                recipient: None,
                data: Vec::new(),
                signature: Signature::ZERO,
            },
        );

        let v = validate(&state, &tx).unwrap();
        apply_staking_no_rollback(&mut state, &tx, &v, 50_000, &exec_ctx(fee_recipient())).unwrap();

        assert_eq!(
            state.get_validator(&addr).unwrap().self_stake,
            Amount::from_sango(150_000).unwrap()
        );
    }

    #[test]
    fn unbond_respects_min_self_stake() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let mut state = NativeState::new();
        let addr = funded_account(&mut state, &kp, 200_000);

        state.set_validator(ValidatorInfo {
            address: addr,
            public_key: kp.public_key(),
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

        // Tentative d'unbond de 10 000 SANGO → resterait 90 000 < 100 000 min.
        let tx = sign_tx(
            &kp,
            Transaction {
                version: 1,
                chain_id: chain(),
                nonce: 0,
                sender: addr,
                public_key: None,
                gas_limit: 50_000,
                max_fee: 20,
                priority_fee: 2,
                value: Amount::from_sango(10_000).unwrap(),
                tx_kind: TxKind::Unbond,
                recipient: None,
                data: Vec::new(),
                signature: Signature::ZERO,
            },
        );

        let v = validate(&state, &tx).unwrap();
        let err =
            apply_staking_no_rollback(&mut state, &tx, &v, 50_000, &exec_ctx(fee_recipient()))
                .unwrap_err();
        assert!(matches!(err, ApplyError::InsufficientSelfStake { .. }));
    }

    // --- Delegate / Undelegate ---------------------------------------------

    #[test]
    fn delegate_and_undelegate() {
        let delegator_kp = NativeKeypair::from_seed([0x01; 32]);
        let validator_kp = NativeKeypair::from_seed([0x02; 32]);

        let mut state = NativeState::new();
        let delegator = funded_account(&mut state, &delegator_kp, 100_000);
        let validator = funded_account(&mut state, &validator_kp, 200_000);

        state.set_validator(ValidatorInfo {
            address: validator,
            public_key: validator_kp.public_key(),
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

        // Delegate 10 000.
        let tx1 = sign_tx(
            &delegator_kp,
            Transaction {
                version: 1,
                chain_id: chain(),
                nonce: 0,
                sender: delegator,
                public_key: None,
                gas_limit: 80_000,
                max_fee: 20,
                priority_fee: 2,
                value: Amount::from_sango(10_000).unwrap(),
                tx_kind: TxKind::Delegate,
                recipient: Some(validator),
                data: Vec::new(),
                signature: Signature::ZERO,
            },
        );
        let v1 = validate(&state, &tx1).unwrap();
        apply_staking_no_rollback(&mut state, &tx1, &v1, 80_000, &exec_ctx(fee_recipient()))
            .unwrap();

        let d = state.get_delegation(&delegator, &validator).unwrap();
        assert_eq!(d.bonded, Amount::from_sango(10_000).unwrap());
        assert_eq!(
            state.get_validator(&validator).unwrap().total_delegated,
            Amount::from_sango(10_000).unwrap()
        );

        // Undelegate 5 000.
        let tx2 = sign_tx(
            &delegator_kp,
            Transaction {
                version: 1,
                chain_id: chain(),
                nonce: 1,
                sender: delegator,
                public_key: None,
                gas_limit: 80_000,
                max_fee: 20,
                priority_fee: 2,
                value: Amount::from_sango(5_000).unwrap(),
                tx_kind: TxKind::Undelegate,
                recipient: Some(validator),
                data: Vec::new(),
                signature: Signature::ZERO,
            },
        );
        let v2 = validate(&state, &tx2).unwrap();
        apply_staking_no_rollback(&mut state, &tx2, &v2, 80_000, &exec_ctx(fee_recipient()))
            .unwrap();

        let d = state.get_delegation(&delegator, &validator).unwrap();
        assert_eq!(d.bonded, Amount::from_sango(5_000).unwrap());
        assert_eq!(d.unbonding, Amount::from_sango(5_000).unwrap());
        assert!(d.unbonding_until.is_some());
        assert_eq!(
            state.get_validator(&validator).unwrap().total_delegated,
            Amount::from_sango(5_000).unwrap()
        );
    }

    #[test]
    fn self_delegation_rejected() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let mut state = NativeState::new();
        let addr = funded_account(&mut state, &kp, 300_000);

        state.set_validator(ValidatorInfo {
            address: addr,
            public_key: kp.public_key(),
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

        let tx = sign_tx(
            &kp,
            Transaction {
                version: 1,
                chain_id: chain(),
                nonce: 0,
                sender: addr,
                public_key: None,
                gas_limit: 80_000,
                max_fee: 20,
                priority_fee: 2,
                value: Amount::from_sango(1_000).unwrap(),
                tx_kind: TxKind::Delegate,
                recipient: Some(addr),
                data: Vec::new(),
                signature: Signature::ZERO,
            },
        );

        let v = validate(&state, &tx).unwrap();
        let err =
            apply_staking_no_rollback(&mut state, &tx, &v, 80_000, &exec_ctx(fee_recipient()))
                .unwrap_err();
        assert_eq!(err, ApplyError::SelfDelegation);
    }

    // --- UpdateCommission ---------------------------------------------------

    #[test]
    fn update_commission_schedules_pending() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let mut state = NativeState::new();
        let addr = funded_account(&mut state, &kp, 200_000);

        state.set_validator(ValidatorInfo {
            address: addr,
            public_key: kp.public_key(),
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

        let tx = sign_tx(
            &kp,
            Transaction {
                version: 1,
                chain_id: chain(),
                nonce: 0,
                sender: addr,
                public_key: None,
                gas_limit: 30_000,
                max_fee: 20,
                priority_fee: 2,
                value: Amount::ZERO,
                tx_kind: TxKind::UpdateCommission,
                recipient: None,
                data: 900u32.to_be_bytes().to_vec(),
                signature: Signature::ZERO,
            },
        );

        let v = validate(&state, &tx).unwrap();
        apply_staking_no_rollback(&mut state, &tx, &v, 30_000, &exec_ctx(fee_recipient())).unwrap();

        let info = state.get_validator(&addr).unwrap();
        assert_eq!(info.commission_bps, 700); // inchangé
        assert_eq!(info.pending_commission_bps, Some(900));
        assert_eq!(
            info.pending_commission_at,
            Some(now() + staking_params::COMMISSION_UPDATE_DELAY_SECS)
        );
    }

    // --- Unjail -------------------------------------------------------------

    #[test]
    fn unjail_after_expiry() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let mut state = NativeState::new();
        let addr = funded_account(&mut state, &kp, 200_000);

        state.set_validator(ValidatorInfo {
            address: addr,
            public_key: kp.public_key(),
            self_stake: Amount::from_sango(100_000).unwrap(),
            total_delegated: Amount::ZERO,
            commission_bps: 700,
            pending_commission_bps: None,
            pending_commission_at: None,
            jailed: true,
            jailed_until: Some(now() - 1),
            downtime_window_start: 0,
            downtime_missed: 0,
        });

        let tx = sign_tx(
            &kp,
            Transaction {
                version: 1,
                chain_id: chain(),
                nonce: 0,
                sender: addr,
                public_key: None,
                gas_limit: 30_000,
                max_fee: 20,
                priority_fee: 2,
                value: Amount::ZERO,
                tx_kind: TxKind::Unjail,
                recipient: None,
                data: Vec::new(),
                signature: Signature::ZERO,
            },
        );

        let v = validate(&state, &tx).unwrap();
        apply_staking_no_rollback(&mut state, &tx, &v, 30_000, &exec_ctx(fee_recipient())).unwrap();

        let info = state.get_validator(&addr).unwrap();
        assert!(!info.jailed);
        assert!(info.jailed_until.is_none());
    }

    #[test]
    fn unjail_before_expiry_fails() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let mut state = NativeState::new();
        let addr = funded_account(&mut state, &kp, 200_000);

        state.set_validator(ValidatorInfo {
            address: addr,
            public_key: kp.public_key(),
            self_stake: Amount::from_sango(100_000).unwrap(),
            total_delegated: Amount::ZERO,
            commission_bps: 700,
            pending_commission_bps: None,
            pending_commission_at: None,
            jailed: true,
            jailed_until: Some(now() + 3600),
            downtime_window_start: 0,
            downtime_missed: 0,
        });

        let tx = sign_tx(
            &kp,
            Transaction {
                version: 1,
                chain_id: chain(),
                nonce: 0,
                sender: addr,
                public_key: None,
                gas_limit: 30_000,
                max_fee: 20,
                priority_fee: 2,
                value: Amount::ZERO,
                tx_kind: TxKind::Unjail,
                recipient: None,
                data: Vec::new(),
                signature: Signature::ZERO,
            },
        );

        let v = validate(&state, &tx).unwrap();
        let err =
            apply_staking_no_rollback(&mut state, &tx, &v, 30_000, &exec_ctx(fee_recipient()))
                .unwrap_err();
        assert!(matches!(err, ApplyError::JailNotExpired { .. }));
    }
}
