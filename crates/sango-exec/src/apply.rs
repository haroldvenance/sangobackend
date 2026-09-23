//! Application des transactions natives au state.
//!
//! ## Mutations d'une transaction
//!
//! 1. débite l'émetteur de `value + total_fee` ;
//! 2. incrémente son nonce ;
//! 3. enregistre sa clé publique si bootstrap ;
//! 4. crédite le destinataire de `value` ;
//! 5. crédite le validateur de `validator_fee = 90 %` ;
//! 6. `burn_fee = 10 %` est **brûlé** — implicitement, en n'étant
//!    crédité à personne ;
//! 7. incrémente `total_burned` et `total_gas_used` dans l'état.
//!
//! ## Atomicité
//!
//! - **Transaction** : [`apply_transfer_with_gas`] est atomique. En cas
//!   d'échec, `state` est restauré.
//! - **Bloc** : [`apply_block_transfers`] et [`apply_block`] sont atomiques
//!   au niveau du bloc entier. Si une seule transaction échoue, tout le
//!   bloc est annulé.
//!
//! ## Compteurs globaux
//!
//! Pour minimiser les écritures SMT, `apply_block` **agrège** les frais
//! brûlés et le gas consommé sur l'ensemble du bloc, et effectue **un seul**
//! appel à `add_burned` et `add_gas_used` en fin de traitement.

use sango_crypto::derive_native_address;
use sango_primitives::{Amount, ChainId32, Hash32, NativeAddress, PublicKey};
use sango_state::{NativeState, StateError};
use sango_tx::{split_fee, ValidatedTransaction};
use sango_types::{Block, EvmLog, LogsBloom, Receipt, ReceiptStatus, Transaction, TxKind};

use crate::error::ApplyError;

/// Gas consommé par un transfert natif simple.
///
/// Constante normative V1 : tout `TX_TRANSFER` consomme exactement ce
/// montant de gas.
pub const NATIVE_TRANSFER_GAS: u64 = 21_000;

/// Contexte d'exécution pour un bloc.
///
/// Contient les paramètres globaux nécessaires à l'application, qui ne
/// sont pas dans le `BlockHeader` lui-même (V1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionContext {
    /// Chain ID attendu pour le réseau.
    pub chain_id: ChainId32,
    /// Base fee courante (base units par gas).
    pub base_fee: u128,
    /// Adresse native du validateur proposant qui perçoit les frais.
    pub fee_recipient: NativeAddress,
    /// Offre initiale du réseau (dérivée du Genesis).
    pub initial_supply: Amount,
    /// Timestamp Unix courant (secondes), utilisé pour les unbondings et
    /// les délais de commission.
    pub current_time: u64,
    /// Hauteur du bloc en cours d'application. Utilisée pour les preuves
    /// (`EvidenceRecord.applied_at_height`) et la distribution des rewards.
    pub current_height: u64,
    /// Active la distribution des récompenses PoS à la fin du bloc.
    ///
    /// `false` par défaut pour les tests unitaires et les premiers blocs
    /// d'un réseau (avant que le pool ne soit activé par le Genesis).
    pub rewards_enabled: bool,
}

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

/// Résultat de l'application d'un ensemble de transactions.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BlockApplyResult {
    /// Transactions appliquées, dans l'ordre.
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

/// Résultat complet de l'application d'un bloc.
///
/// Produit par [`apply_block`] : inclut les receipts, les agrégats
/// financiers, l'offre courante et le `state_root` (racine de l'état natif
/// **après** application du bloc).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockExecutionResult {
    /// Agrégats financiers et liste des transactions appliquées.
    pub apply_result: BlockApplyResult,
    /// Un receipt par transaction, dans l'ordre du bloc.
    pub receipts: Vec<Receipt>,
    /// Cumul des frais brûlés (base units).
    pub fee_burned: u128,
    /// Cumul des frais versés au validateur (base units).
    pub fee_paid: u128,
    /// Cumul du gas consommé.
    pub gas_used: u64,
    /// Cumul global des SANGO brûlés depuis le genesis (base units).
    pub total_burned_after: Amount,
    /// Cumul global du gas consommé depuis le genesis.
    pub total_gas_used_after: u64,
    /// Offre courante après application :
    /// `initial_supply − total_burned`.
    pub current_supply: Amount,
    /// Racine de l'état natif après application.
    pub native_state_root: Hash32,
    /// Racine des receipts dans le bloc. **Placeholder** (`Hash32::ZERO`)
    /// tant que le MPT EVM n'est pas implémenté.
    pub receipt_root: Hash32,
    /// Récompense PoS distribuée au proposant pour ce bloc (`None` si
    /// désactivé ou pool épuisé).
    pub pos_rewards: Option<crate::rewards::RewardDistribution>,
}

// --- API mono-transaction --------------------------------------------------

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
///
/// Met à jour `total_burned` et `total_gas_used` dans l'état.
pub fn apply_transfer_with_gas(
    state: &mut NativeState,
    tx: &Transaction,
    validated: &ValidatedTransaction,
    gas_used: u64,
    fee_recipient: NativeAddress,
) -> Result<AppliedTransaction, ApplyError> {
    let snapshot = state.clone();
    match apply_transfer_no_rollback(state, tx, validated, gas_used, fee_recipient) {
        Ok(applied) => {
            // Compteurs globaux.
            if let Err(e) = state.add_burned(Amount::from_base_units(applied.burn_fee)) {
                *state = snapshot;
                return Err(ApplyError::State(e));
            }
            if let Err(e) = state.add_gas_used(applied.gas_used) {
                *state = snapshot;
                return Err(ApplyError::State(e));
            }
            Ok(applied)
        }
        Err(e) => {
            *state = snapshot;
            Err(e)
        }
    }
}

// --- API multi-transactions (block) ---------------------------------------

/// Applique une séquence de transactions natives **atomiquement**.
///
/// Supporte `TX_TRANSFER` et tous les `TxKind` de staking. Agrège les frais
/// brûlés et le gas en une seule écriture SMT. Si **une seule** transaction
/// échoue, tout le bloc est annulé.
///
/// Ce point d'entrée est destiné aux tests et cas où le `BlockHeader`
/// n'est pas nécessaire. Pour l'application complète d'un bloc, voir
/// [`apply_block`].
pub fn apply_block_transfers(
    state: &mut NativeState,
    txs: &[Transaction],
    validated: &[ValidatedTransaction],
    ctx: &ExecutionContext,
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
        let gas_used = crate::staking::gas_for(tx.tx_kind).unwrap_or(NATIVE_TRANSFER_GAS);
        match apply_tx_no_rollback(state, tx, v, gas_used, ctx) {
            Ok(applied) => {
                result.total_gas_used = result
                    .total_gas_used
                    .checked_add(applied.gas_used)
                    .ok_or(ApplyError::TotalGasUsedOverflow)?;
                result.total_fee = result
                    .total_fee
                    .checked_add(applied.total_fee)
                    .ok_or(ApplyError::TotalFeeOverflow)?;
                result.total_validator_fee = result
                    .total_validator_fee
                    .checked_add(applied.validator_fee)
                    .ok_or(ApplyError::TotalFeeOverflow)?;
                result.total_burned = result
                    .total_burned
                    .checked_add(applied.burn_fee)
                    .ok_or(ApplyError::TotalFeeOverflow)?;
                result.applied.push(applied);
            }
            Err(e) => {
                *state = snapshot;
                return Err(e);
            }
        }
    }

    // Écriture agrégée des compteurs globaux.
    if let Err(e) = state.add_burned(Amount::from_base_units(result.total_burned)) {
        *state = snapshot;
        return Err(ApplyError::State(e));
    }
    if let Err(e) = state.add_gas_used(result.total_gas_used) {
        *state = snapshot;
        return Err(ApplyError::State(e));
    }

    Ok(result)
}

/// Applique un bloc complet : transactions + receipts + compteurs globaux.
///
/// **Atomique** : en cas d'échec, `state` est restauré.
///
/// ## Limites V1
///
/// - `TX_TRANSFER` et les `TxKind` de staking sont supportés.
/// - Les `TX_CONTRACT_*` seront gérés par la couche EVM (à venir).
/// - `receipt_root` est un placeholder `Hash32::ZERO` tant que le MPT EVM
///   n'est pas implémenté.
pub fn apply_block(
    state: &mut NativeState,
    block: &Block,
    validated: &[ValidatedTransaction],
    ctx: &ExecutionContext,
    participants: &[NativeAddress],
) -> Result<BlockExecutionResult, ApplyError> {
    if block.transactions.len() != validated.len() {
        return Err(ApplyError::LengthMismatch {
            txs: block.transactions.len(),
            validated: validated.len(),
        });
    }

    let snapshot = state.clone();

    // 0. Suivi de la participation (downtime).
    //
    // Déterministe : tous les nœuds voient le même CommitCertificate (donc
    // les mêmes participants) et évaluent la même fenêtre au même moment.
    // Fait **avant** l'application des txs pour utiliser l'ensemble actif
    // tel qu'il était au début du bloc.
    {
        let active: Vec<NativeAddress> = state
            .all_validators()
            .into_iter()
            .filter(|v| !v.jailed)
            .map(|v| v.address)
            .collect();
        if let Err(e) = crate::downtime::record_participation(state, &active, participants, ctx) {
            *state = snapshot;
            return Err(e);
        }
    }

    // 1. Appliquer les transactions (sans toucher aux compteurs globaux).
    let mut applied: Vec<AppliedTransaction> = Vec::with_capacity(validated.len());
    let mut total_gas_used: u64 = 0;
    let mut total_fee: u128 = 0;
    let mut total_validator_fee: u128 = 0;
    let mut total_burned: u128 = 0;

    for (tx, v) in block.transactions.iter().zip(validated.iter()) {
        let gas_used = crate::staking::gas_for(tx.tx_kind).unwrap_or(NATIVE_TRANSFER_GAS);
        match apply_tx_no_rollback(state, tx, v, gas_used, ctx) {
            Ok(a) => {
                total_gas_used = total_gas_used
                    .checked_add(a.gas_used)
                    .ok_or(ApplyError::TotalGasUsedOverflow)?;
                total_fee = total_fee
                    .checked_add(a.total_fee)
                    .ok_or(ApplyError::TotalFeeOverflow)?;
                total_validator_fee = total_validator_fee
                    .checked_add(a.validator_fee)
                    .ok_or(ApplyError::TotalFeeOverflow)?;
                total_burned = total_burned
                    .checked_add(a.burn_fee)
                    .ok_or(ApplyError::TotalFeeOverflow)?;
                applied.push(a);
            }
            Err(e) => {
                *state = snapshot;
                return Err(e);
            }
        }
    }

    // 2. Mettre à jour les compteurs globaux en une seule passe.
    if let Err(e) = state.add_burned(Amount::from_base_units(total_burned)) {
        *state = snapshot;
        return Err(ApplyError::State(e));
    }
    if let Err(e) = state.add_gas_used(total_gas_used) {
        *state = snapshot;
        return Err(ApplyError::State(e));
    }

    // 2bis. Distribuer les récompenses PoS au proposeur.
    let pos_rewards = match crate::rewards::distribute_block_rewards(state, ctx.fee_recipient, ctx)
    {
        Ok(r) => r,
        Err(e) => {
            *state = snapshot;
            return Err(e);
        }
    };

    // 3. Générer les receipts (cumulative_gas_used par ordre).
    let mut receipts = Vec::with_capacity(applied.len());
    let mut cumulative: u64 = 0;
    for a in &applied {
        cumulative = cumulative
            .checked_add(a.gas_used)
            .ok_or(ApplyError::TotalGasUsedOverflow)?;
        receipts.push(Receipt {
            tx_hash: a.tx_hash,
            status: ReceiptStatus::Success,
            cumulative_gas_used: cumulative,
            gas_used: a.gas_used,
            contract_address: None,
            logs_bloom: LogsBloom::EMPTY,
            logs: Vec::<EvmLog>::new(),
        });
    }

    // 4. Offre courante après application.
    let total_burned_after = state.total_burned();
    let current_supply =
        state
            .current_supply(ctx.initial_supply)
            .ok_or(ApplyError::CurrentSupplyUnderflow {
                initial: ctx.initial_supply.base_units(),
                burned: total_burned_after.base_units(),
            })?;

    Ok(BlockExecutionResult {
        apply_result: BlockApplyResult {
            applied,
            total_gas_used,
            total_fee,
            total_validator_fee,
            total_burned,
        },
        receipts,
        fee_burned: total_burned,
        fee_paid: total_validator_fee,
        gas_used: total_gas_used,
        total_burned_after,
        total_gas_used_after: state.total_gas_used(),
        current_supply,
        native_state_root: state.native_state_root(),
        // TODO(MPT): à remplacer par le vrai MPT des receipts.
        receipt_root: Hash32::ZERO,
        pos_rewards,
    })
}

// --- Implémentation sans rollback ------------------------------------------

/// Implémentation sans rollback.
///
/// Ne touche **pas** aux compteurs globaux (`total_burned`,
/// `total_gas_used`) : c'est la responsabilité de l'appelant de les
/// mettre à jour après succès (éventuellement de façon agrégée).
pub(crate) fn apply_transfer_no_rollback(
    state: &mut NativeState,
    tx: &Transaction,
    validated: &ValidatedTransaction,
    gas_used: u64,
    fee_recipient: NativeAddress,
) -> Result<AppliedTransaction, ApplyError> {
    // (1) Structure.
    if tx.tx_kind.is_staking() {
        return Err(ApplyError::UnsupportedTxKind(tx.tx_kind));
    }
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

    // (3) Vérifications préalables.
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

    // (4) Mutations.
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

/// Dispatcher : applique n'importe quelle transaction native.
///
/// - `TxKind::Transfer` → [`apply_transfer_no_rollback`]
/// - `TxKind` de staking → [`crate::staking::apply_staking_no_rollback`]
/// - Autres → [`ApplyError::UnsupportedTxKind`]
pub fn apply_tx_no_rollback(
    state: &mut NativeState,
    tx: &Transaction,
    validated: &ValidatedTransaction,
    gas_used: u64,
    ctx: &ExecutionContext,
) -> Result<AppliedTransaction, ApplyError> {
    if tx.tx_kind == TxKind::Transfer {
        return apply_transfer_no_rollback(state, tx, validated, gas_used, ctx.fee_recipient);
    }
    if tx.tx_kind.is_staking() {
        return crate::staking::apply_staking_no_rollback(state, tx, validated, gas_used, ctx);
    }
    Err(ApplyError::UnsupportedTxKind(tx.tx_kind))
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
    use sango_types::{BlockHeader, NativeAccount, Transaction, TxKind};

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

    fn exec_ctx() -> ExecutionContext {
        ExecutionContext {
            chain_id: chain(),
            base_fee: 10,
            fee_recipient: validator(),
            initial_supply: Amount::from_sango(1_000_000_000).unwrap(),
            current_time: 1_700_000_000,
            current_height: 0,
            rewards_enabled: false,
        }
    }

    fn sample_header() -> BlockHeader {
        BlockHeader {
            version: 1,
            chain_id: chain(),
            epoch: sango_primitives::Epoch::new(0),
            height: sango_primitives::Height::new(1),
            round: sango_primitives::Round::new(0),
            previous_block_hash: Hash32::from_bytes([0x22; 32]),
            timestamp: 1_700_000_000,
            proposer_address: validator(),
            transaction_root: Hash32::ZERO,
            state_root: Hash32::ZERO,
            receipt_root: Hash32::ZERO,
            gas_used: 0,
            gas_limit: 30_000_000,
            base_fee: 1,
        }
    }

    // --- Mono-transaction ---------------------------------------------------

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

        // Compteurs globaux mis à jour.
        assert_eq!(state.total_burned(), Amount::from_base_units(25_200));
        assert_eq!(state.total_gas_used(), NATIVE_TRANSFER_GAS);
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
        apply_transfer(&mut state, &tx, &v, validator()).unwrap();

        assert_eq!(
            state.balance_of(&sender),
            Amount::from_base_units(1_000_000 - 252_000)
        );
        assert_eq!(state.total_burned(), Amount::from_base_units(25_200));
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

        state.set_account(NativeAccount::from_public_key(pk, Amount::ZERO, 0));
        let root_before = state.native_state_root();

        let err = apply_transfer(&mut state, &tx, &v, validator()).unwrap_err();
        assert!(matches!(err, ApplyError::InsufficientBalance { .. }));
        assert_eq!(state.balance_of(&sender), Amount::ZERO);
        assert_eq!(state.nonce_of(&sender), 0);
        assert_eq!(state.native_state_root(), root_before);
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

    // --- Multi-transactions (apply_block_transfers) -------------------------

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
            apply_block_transfers(&mut state, &[tx1, tx2], &[v1, v2], &exec_ctx()).unwrap();

        assert_eq!(result.applied.len(), 2);
        assert_eq!(result.total_fee, 2 * 252_000);
        assert_eq!(result.total_validator_fee, 2 * 226_800);
        assert_eq!(result.total_burned, 2 * 25_200);
        assert_eq!(state.nonce_of(&s1), 1);
        assert_eq!(state.nonce_of(&s2), 1);
        // Compteurs agrégés sur le bloc.
        assert_eq!(state.total_burned(), Amount::from_base_units(2 * 25_200));
        assert_eq!(state.total_gas_used(), 2 * NATIVE_TRANSFER_GAS);
    }

    #[test]
    fn apply_block_is_atomic_on_failure() {
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

        state.set_account(NativeAccount::from_public_key(
            kp2.public_key(),
            Amount::ZERO,
            0,
        ));
        let root_before = state.native_state_root();

        let err =
            apply_block_transfers(&mut state, &[tx1, tx2], &[v1, v2], &exec_ctx()).unwrap_err();
        assert!(matches!(err, ApplyError::InsufficientBalance { .. }));
        assert_eq!(state.native_state_root(), root_before);
        assert_eq!(state.nonce_of(&s1), 0);
        assert_eq!(state.nonce_of(&s2), 0);
        assert_eq!(state.total_burned(), Amount::ZERO);
        assert_eq!(state.total_gas_used(), 0);
    }

    #[test]
    fn apply_block_length_mismatch() {
        let mut state = NativeState::new();
        let r = apply_block_transfers(&mut state, &[], &[], &exec_ctx()).unwrap();
        assert!(r.applied.is_empty());

        let kp = NativeKeypair::from_seed([0x42; 32]);
        let tx = bootstrap_tx(&kp, 0, 1);
        let err = apply_block_transfers(&mut state, &[tx], &[], &exec_ctx()).unwrap_err();
        assert_eq!(
            err,
            ApplyError::LengthMismatch {
                txs: 1,
                validated: 0
            }
        );
    }

    // --- apply_block --------------------------------------------------------

    #[test]
    fn apply_block_empty() {
        let mut state = NativeState::new();
        let block = Block {
            header: sample_header(),
            transactions: Vec::new(),
        };
        let r = apply_block(&mut state, &block, &[], &exec_ctx(), &[]).unwrap();
        assert_eq!(r.apply_result.applied.len(), 0);
        assert_eq!(r.receipts.len(), 0);
        assert_eq!(r.gas_used, 0);
        assert_eq!(r.fee_burned, 0);
        assert_eq!(r.current_supply, exec_ctx().initial_supply);
        assert_eq!(r.total_burned_after, Amount::ZERO);
        assert_eq!(r.total_gas_used_after, 0);
        assert_eq!(r.receipt_root, Hash32::ZERO);
    }

    #[test]
    fn apply_block_two_transfers_with_receipts() {
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

        let block = Block {
            header: sample_header(),
            transactions: vec![tx1.clone(), tx2.clone()],
        };
        let r = apply_block(&mut state, &block, &[v1, v2], &exec_ctx(), &[]).unwrap();

        assert_eq!(r.receipts.len(), 2);
        assert_eq!(r.receipts[0].tx_hash, tx1.hash());
        assert_eq!(r.receipts[1].tx_hash, tx2.hash());
        // cumulative_gas_used croissant.
        assert_eq!(r.receipts[0].cumulative_gas_used, NATIVE_TRANSFER_GAS);
        assert_eq!(r.receipts[1].cumulative_gas_used, 2 * NATIVE_TRANSFER_GAS);
        assert_eq!(r.receipts[0].gas_used, NATIVE_TRANSFER_GAS);
        assert_eq!(r.receipts[0].status, ReceiptStatus::Success);
        assert_eq!(r.receipts[0].contract_address, None);
        assert!(r.receipts[0].logs.is_empty());
        assert!(r.receipts[0].logs_bloom.is_empty());

        assert_eq!(r.gas_used, 2 * NATIVE_TRANSFER_GAS);
        assert_eq!(r.fee_burned, 2 * 25_200);
        assert_eq!(r.fee_paid, 2 * 226_800);
        assert_eq!(r.total_burned_after, Amount::from_base_units(2 * 25_200));
        assert_eq!(r.total_gas_used_after, 2 * NATIVE_TRANSFER_GAS);
    }

    #[test]
    fn apply_block_updates_current_supply() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let sender = derive_native_address(&kp.public_key());

        let mut state = NativeState::new();
        state
            .credit(sender, Amount::from_base_units(1_000_000))
            .unwrap();

        let tx = bootstrap_tx(&kp, 0, 100);
        let v = validate(&state, &tx).unwrap();
        let block = Block {
            header: sample_header(),
            transactions: vec![tx],
        };
        let initial = exec_ctx().initial_supply;
        let r = apply_block(&mut state, &block, &[v], &exec_ctx(), &[]).unwrap();

        let expected_burned = Amount::from_base_units(25_200);
        assert_eq!(r.total_burned_after, expected_burned);
        assert_eq!(
            r.current_supply.base_units(),
            initial.base_units() - expected_burned.base_units()
        );
    }

    #[test]
    fn apply_block_full_is_atomic_on_failure() {
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

        state.set_account(NativeAccount::from_public_key(
            kp2.public_key(),
            Amount::ZERO,
            0,
        ));
        let root_before = state.native_state_root();

        let block = Block {
            header: sample_header(),
            transactions: vec![tx1, tx2],
        };
        let err = apply_block(&mut state, &block, &[v1, v2], &exec_ctx(), &[]).unwrap_err();
        assert!(matches!(err, ApplyError::InsufficientBalance { .. }));
        assert_eq!(state.native_state_root(), root_before);
        assert_eq!(state.total_burned(), Amount::ZERO);
        assert_eq!(state.total_gas_used(), 0);
    }

    #[test]
    fn apply_block_full_length_mismatch() {
        let mut state = NativeState::new();
        let block = Block {
            header: sample_header(),
            transactions: Vec::new(),
        };
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let tx = bootstrap_tx(&kp, 0, 1);
        let _ = tx;
        let v = ValidatedTransaction {
            tx_hash: Hash32::ZERO,
            sender: NativeAddress::from_bytes([0xaa; 20]),
            effective_gas_price: 12,
            max_total_fee: 252_000,
            value: 100,
            bootstrap_public_key: None,
        };
        let err = apply_block(&mut state, &block, &[v], &exec_ctx(), &[]).unwrap_err();
        assert_eq!(
            err,
            ApplyError::LengthMismatch {
                txs: 0,
                validated: 1
            }
        );
    }

    #[test]
    fn apply_block_state_root_matches_native_root() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let sender = derive_native_address(&kp.public_key());

        let mut state = NativeState::new();
        state
            .credit(sender, Amount::from_base_units(1_000_000))
            .unwrap();

        let tx = bootstrap_tx(&kp, 0, 100);
        let v = validate(&state, &tx).unwrap();
        let block = Block {
            header: sample_header(),
            transactions: vec![tx],
        };
        let r = apply_block(&mut state, &block, &[v], &exec_ctx(), &[]).unwrap();

        assert_eq!(r.native_state_root, state.native_state_root());
    }

    #[test]
    fn apply_block_integrated_downtime() {
        // Vérifie que apply_block déclenche bien le suivi de participation.
        use sango_types::ValidatorInfo;

        let kp_a = NativeKeypair::from_seed([0xa1; 32]);
        let kp_b = NativeKeypair::from_seed([0xb1; 32]);
        let a = derive_native_address(&kp_a.public_key());
        let b = derive_native_address(&kp_b.public_key());

        let mut state = NativeState::new();
        let mk = |addr, pk| ValidatorInfo {
            address: addr,
            public_key: pk,
            self_stake: Amount::from_sango(100_000).unwrap(),
            total_delegated: Amount::ZERO,
            commission_bps: 700,
            pending_commission_bps: None,
            pending_commission_at: None,
            jailed: false,
            jailed_until: None,
            downtime_window_start: 1,
            downtime_missed: 0,
        };
        state.set_validator(mk(a, kp_a.public_key()));
        state.set_validator(mk(b, kp_b.public_key()));

        // Bloc vide, seul A participe.
        let mut h = sample_header();
        h.height = sango_primitives::Height::new(1);
        let block = Block {
            header: h,
            transactions: Vec::new(),
        };

        let ctx = exec_ctx();
        apply_block(&mut state, &block, &[], &ctx, &[a]).unwrap();

        let info_a = state.get_validator(&a).unwrap();
        let info_b = state.get_validator(&b).unwrap();
        assert_eq!(info_a.downtime_missed, 0, "A a participé");
        assert_eq!(info_b.downtime_missed, 1, "B a manqué");
    }

    #[test]
    fn apply_block_empty_participants_increments_all() {
        use sango_types::ValidatorInfo;
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let addr = derive_native_address(&kp.public_key());

        let mut state = NativeState::new();
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
            downtime_window_start: 1,
            downtime_missed: 0,
        });

        let mut h = sample_header();
        h.height = sango_primitives::Height::new(1);
        let block = Block {
            header: h,
            transactions: Vec::new(),
        };
        apply_block(&mut state, &block, &[], &exec_ctx(), &[]).unwrap();

        assert_eq!(state.get_validator(&addr).unwrap().downtime_missed, 1);
    }
}
