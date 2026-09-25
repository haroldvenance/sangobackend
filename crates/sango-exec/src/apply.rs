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
//!
//! ## Déterminisme
//!
//! `apply_block` doit produire **exactement** le même `native_state_root`
//! sur tous les nœuds pour un bloc donné. En V1, deux sous-systèmes
//! dépendent d'observations locales non déterministes :
//!
//! - le **downtime** dépend du `CommitCertificate`, dont la composition
//!   exacte peut différer d'un nœud à l'autre (ordre réseau) ;
//! - la **distribution des rewards PoS** dépend du pool et des
//!   participants locaux.
//!
//! Les deux sont donc pilotés par des flags dans [`ExecutionContext`]
//! (`downtime_enabled`, `rewards_enabled`) qui doivent rester `false`
//! tant que ces données ne sont pas incluses *dans* le bloc.
//!
//! La finalisation des unbondings, en revanche, est **déterministe** : elle
//! ne dépend que de `ctx.current_time` (issu du header du bloc) et de
//! l'état. Elle est donc toujours activée.

use sango_codec::Encode;
use sango_crypto::derive_native_address;
use sango_evm::{evm_transact, EvmBlockEnv, EvmState, TxEnvExtras};
use sango_primitives::{Amount, ChainId32, EvmAddress, Hash32, NativeAddress, PublicKey, U256};
use sango_state::{NativeState, StateError};
use sango_tx::{split_fee, ValidatedTransaction as ValidatedNativeTransaction};
use sango_types::{Block, EvmLog, LogsBloom, Receipt, ReceiptStatus, Transaction, Tx, TxKind};

use crate::error::ApplyError;

/// Chain ID EVM par défaut (« SANGO » en ASCII).
pub const DEFAULT_EVM_CHAIN_ID: u64 = 0x53_41_4e_47_4f;

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
    /// **Doit rester `false`** tant que la distribution dépend de données
    /// locales (pool calculé localement, participants locaux) : sinon le
    /// `state_root` diverge entre nœuds et le consensus se bloque.
    pub rewards_enabled: bool,
    /// Active le suivi de la participation (downtime).
    ///
    /// **Doit rester `false`** tant que le `CommitCertificate` n'est pas
    /// diffusé *dans le bloc* pour être identique partout : sinon le
    /// `state_root` diverge.
    pub downtime_enabled: bool,
    /// Chain ID EVM (u64), utilisé par revm (`CfgEnv::chain_id`).
    ///
    /// Distinct du `chain_id` natif (32 bytes). En V1, valeur par défaut :
    /// [`DEFAULT_EVM_CHAIN_ID`] (« SANGO » en ASCII).
    pub evm_chain_id: u64,
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

/// Résultat d'exécution d'une transaction EVM.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppliedEvmTx {
    /// Hash canonique de la transaction.
    pub tx_hash: Hash32,
    /// Adresse EVM de l'émetteur (récupérée de la signature).
    pub sender: EvmAddress,
    /// Gas consommé par l'exécution.
    pub gas_used: u64,
    /// Prix effectif par unité de gas (règle Sango unifiée).
    pub effective_gas_price: U256,
    /// `gas_used * effective_gas_price`.
    ///
    /// **Note** : ce montant est **débité par revm** dans l'`EvmState`.
    /// Il n'est **pas** reporté dans `NativeState.total_burned` — voir
    /// [`BlockExecutionResult`] pour la sémantique exacte.
    pub total_fee: u128,
    /// Logs émis par l'exécution.
    pub logs: Vec<EvmLog>,
    /// Adresse du contrat créé, si applicable.
    pub contract_address: Option<EvmAddress>,
    /// Données de retour (call uniquement).
    pub output: Vec<u8>,
    /// Succès ou échec (REVERT / HALT).
    pub success: bool,
}

/// Transaction appliquée : native ou EVM.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Applied {
    /// Transaction native Sango.
    Native(AppliedTransaction),
    /// Transaction EVM.
    Evm(AppliedEvmTx),
}

impl Applied {
    /// Hash canonique.
    #[must_use]
    pub fn tx_hash(&self) -> Hash32 {
        match self {
            Applied::Native(a) => a.tx_hash,
            Applied::Evm(a) => a.tx_hash,
        }
    }

    /// Gas consommé.
    #[must_use]
    pub fn gas_used(&self) -> u64 {
        match self {
            Applied::Native(a) => a.gas_used,
            Applied::Evm(a) => a.gas_used,
        }
    }

    /// Frais totaux (`gas_used * effective_gas_price`).
    ///
    /// Pour les EVM, ce montant est débité dans l'`EvmState` par revm ;
    /// il n'apparaît pas dans `NativeState`.
    #[must_use]
    pub fn total_fee(&self) -> u128 {
        match self {
            Applied::Native(a) => a.total_fee,
            Applied::Evm(a) => a.total_fee,
        }
    }

    /// Part validateur (90 %).
    ///
    /// Renvoie `0` pour les EVM : la répartition des frais EVM est gérée
    /// par revm via le `coinbase`.
    #[must_use]
    pub fn validator_fee(&self) -> u128 {
        match self {
            Applied::Native(a) => a.validator_fee,
            Applied::Evm(_) => 0,
        }
    }

    /// Part brûlée (10 %).
    ///
    /// Renvoie `0` pour les EVM : voir [`Self::validator_fee`].
    #[must_use]
    pub fn burn_fee(&self) -> u128 {
        match self {
            Applied::Native(a) => a.burn_fee,
            Applied::Evm(_) => 0,
        }
    }
}

/// Transaction EVM validée : contient les champs dérivés nécessaires à
/// l'exécution revm.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedEvmTransaction {
    /// Hash canonique de la tx.
    pub tx_hash: Hash32,
    /// Sender récupéré cryptographiquement de la signature.
    pub sender: EvmAddress,
    /// Prix effectif par unité de gas (règle Sango unifiée).
    pub effective_gas_price: U256,
}

/// Transaction validée : native ou EVM.
///
/// Indexée **1:1** avec `block.transactions`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValidatedTransaction {
    /// Transaction native (validation via `sango-tx`).
    Native(ValidatedNativeTransaction),
    /// Transaction EVM (validation consensus minimale + recovery).
    Evm(ValidatedEvmTransaction),
}

/// Résultat de l'application d'un ensemble de transactions.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BlockApplyResult {
    /// Transactions appliquées, dans l'ordre.
    pub applied: Vec<Applied>,
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
    /// Racine de l'état natif (SMT Sango) après application.
    pub native_state_root: Hash32,
    /// Racine MPT Ethereum de l'état EVM après application.
    ///
    /// En V1 (EVM non encore branché) : [`empty_evm_state_root`].
    pub evm_state_root: Hash32,
    /// `state_root` global du header :
    ///
    /// ```text
    /// Keccak256("SANGO/STATE/ROOT/V1" || native_state_root || evm_state_root)
    /// ```
    pub state_root: Hash32,
    /// Racine MPT Ethereum des transactions du bloc.
    ///
    /// Formule normative V1 (natif uniquement) :
    ///
    /// ```text
    /// transaction_root = MPT_root({ RLP(index) → canonical_sango_tx_bytes })
    /// ```
    ///
    /// Quand l'EVM arrivera, les txs EVM fourniront directement
    /// `ethereum_typed_transaction_bytes` (déjà RLP), et la racine
    /// deviendra un MPT Ethereum hétérogène natif/EVM.
    pub transaction_root: Hash32,
    /// Racine MPT Ethereum des receipts du bloc.
    ///
    /// **Placeholder** en V1 tant que le MPT des receipts n'est pas
    /// implémenté (étape 3b). La valeur `Hash32::ZERO` n'est **pas** la
    /// définition normative du root vide — c'est un marqueur provisoire
    /// qui sera remplacé par `Keccak256(RLP(""))` une fois le calcul en
    /// place.
    pub receipt_root: Hash32,
    /// Récompense PoS distribuée au proposant pour ce bloc (`None` si
    /// désactivé ou pool épuisé).
    pub pos_rewards: Option<crate::rewards::RewardDistribution>,
}

// --- Transaction root ------------------------------------------------------

/// Calcule la racine MPT Ethereum-compatible des transactions du bloc.
///
/// ## Formule normative (V1, natif uniquement)
///
/// ```text
/// key_i   = RLP(i)
/// value_i = canonical_sango_tx_bytes(i)
/// ```
///
/// **Pas** de RLP supplémentaire autour de `value` : en V1 les seules
/// txs sont natives, et leur représentation canonique est celle du
/// `sango-codec` (pas RLP). Quand les txs EVM arriveront, elles
/// fourniront directement leurs bytes Ethereum typed (déjà RLP).
///
/// ## Ordre
///
/// L'ordre des transactions est **consensus-critical** : l'index `i`
/// fait partie de la clé. On itère donc `txs` tel quel, sans tri.
#[must_use]
pub fn compute_transaction_root(txs: &[Tx]) -> Hash32 {
    let values: Vec<Vec<u8>> = txs.iter().map(|tx| tx.canonical_bytes()).collect();
    sango_mpt::transaction_root(&values)
}

// --- Receipts --------------------------------------------------------------

/// Construit les receipts d'un bloc à partir des transactions appliquées.
///
/// `cumulative_gas_used` est calculé séquentiellement, dans l'ordre
/// exact des transactions du bloc. C'est la sémantique Ethereum.
///
/// ## Source unique de vérité
///
/// Cette fonction est **partagée** entre le proposeur (qui simule
/// l'exécution du bloc candidat) et le validateur (qui applique le
/// bloc reçu). Les deux produisent donc exactement les mêmes receipts
/// à partir de la même séquence d'`AppliedTransaction`, ce qui garantit
/// que le `receipt_root` calculé par le proposeur est vérifiable par le
/// validateur.
///
/// ## Défensive `saturating_add`
///
/// `apply_block` vérifie déjà que `total_gas_used` ne déborde pas
/// `u64::MAX`. On utilise `saturating_add` par sûreté : un débordement
/// silencieux vaut mieux qu'un panic dans du code consensus-critical, et
/// ce cas ne peut se produire que si le calcul amont a un bug.
#[must_use]
pub fn build_receipts(applied: &[Applied]) -> Vec<Receipt> {
    let mut out = Vec::with_capacity(applied.len());
    let mut cumulative: u64 = 0;
    for a in applied {
        cumulative = cumulative.saturating_add(a.gas_used());
        match a {
            Applied::Native(n) => {
                out.push(Receipt {
                    tx_hash: n.tx_hash,
                    status: ReceiptStatus::Success,
                    cumulative_gas_used: cumulative,
                    gas_used: n.gas_used,
                    contract_address: None,
                    logs_bloom: LogsBloom::EMPTY,
                    logs: Vec::<EvmLog>::new(),
                });
            }
            Applied::Evm(e) => {
                let logs = e.logs.clone();
                let bloom = LogsBloom::from_logs(&logs);
                let status = if e.success {
                    ReceiptStatus::Success
                } else {
                    ReceiptStatus::Failure
                };
                out.push(Receipt {
                    tx_hash: e.tx_hash,
                    status,
                    cumulative_gas_used: cumulative,
                    gas_used: e.gas_used,
                    contract_address: e.contract_address,
                    logs_bloom: bloom,
                    logs,
                });
            }
        }
    }
    out
}

/// Calcule la racine MPT Ethereum-compatible des receipts du bloc.
///
/// ## Formule normative (V1)
///
/// ```text
/// key_i   = RLP(i)
/// value_i = canonical_sango_receipt_bytes(i)
/// ```
///
/// Le format canonique d'un receipt est celui de `sango-codec` (pas RLP).
/// Le MPT est Ethereum-compatible, mais la **valeur** de chaque feuille
/// est le receipt Sango encodé tel quel — cohérent avec la décision de 3a
/// pour les transactions natives.
#[must_use]
pub fn compute_receipt_root(receipts: &[Receipt]) -> Hash32 {
    let values: Vec<Vec<u8>> = receipts.iter().map(|r| r.encode_to_vec()).collect();
    sango_mpt::transaction_root(&values)
}

// --- EVM state root --------------------------------------------------------

/// Calcule la racine MPT Ethereum d'un état EVM.
///
/// ## Contrat protocolaire
///
/// ```text
/// compute_evm_state_root(state) = state.state_root()
/// ```
///
/// **Pas de branche `is_empty`** : `EvmState::state_root()` retourne
/// naturellement `sango_mpt::empty_root()` lorsque le trie des comptes est
/// vide (`mpt_root(&[]) == empty_root()`). Une **unique** définition,
/// sans branche spéciale.
///
/// ## Usage en V1
///
/// En V1, aucun compte EVM n'existe. `apply_block` appelle donc
/// `compute_evm_state_root(&EvmState::new())`, qui retourne
/// `empty_root()`. Quand l'EVM sera branché (4c), on passera un
/// `EvmState` peuplé — **sans changement de formule**.
#[must_use]
pub fn compute_evm_state_root(state: &sango_evm::EvmState) -> Hash32 {
    state.state_root()
}

/// Racine MPT Ethereum de l'état EVM **vide**.
///
/// Égale à `sango_mpt::empty_root()` = `Keccak256(RLP(""))`.
///
/// **Ce n'est PAS `Hash32::ZERO`.** Voir [`compute_evm_state_root`] pour
/// la formule normative.
#[must_use]
pub fn empty_evm_state_root() -> Hash32 {
    compute_evm_state_root(&sango_evm::EvmState::new())
}

// --- API mono-transaction --------------------------------------------------

/// Applique un transfert natif avec le gas standard.
pub fn apply_transfer(
    state: &mut NativeState,
    tx: &Transaction,
    validated: &ValidatedNativeTransaction,
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
    validated: &ValidatedNativeTransaction,
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
    validated: &[ValidatedNativeTransaction],
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
                result.applied.push(Applied::Native(applied));
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
/// - `transaction_root` est calculé via un MPT Ethereum-compatible
///   (voir [`compute_transaction_root`]).
/// - `receipt_root` est calculé via un MPT Ethereum-compatible à partir
///   des receipts construits par [`build_receipts`].
///
/// ## Déterminisme
///
/// Le `native_state_root` produit **doit** être identique sur tous les
/// nœuds. Les sous-systèmes non déterministes (downtime, rewards) sont
/// conditionnés par `ctx.downtime_enabled` / `ctx.rewards_enabled`. La
/// libération des unbondings est toujours active (déterministe).
pub fn apply_block(
    state: &mut NativeState,
    evm_state: &mut EvmState,
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
    let evm_snapshot = evm_state.clone();

    // 0a. Appliquer les evidences AVANT les transactions.
    //
    // Chaque evidence est un slashing déterministe. Comme elles font
    // partie du `Block`, tous les nœuds observent les mêmes.
    for evidence in &block.evidences {
        if let Err(e) = crate::slashing::apply_evidence(state, evidence, ctx) {
            *state = snapshot;
            return Err(e);
        }
    }

    // 0b. Suivi de la participation (downtime).
    //
    // **Désactivé par défaut** : en V1, `participants` provient du
    // `CommitCertificate` local, dont la composition exacte (quels
    // precommits ont été observés) peut différer d'un nœud à l'autre à
    // cause du timing réseau. L'activer rendrait l'exécution non
    // déterministe et ferait diverger les `state_root` — bloquant le
    // consensus.
    //
    // À réactiver le jour où le certificat est **inclus dans le bloc**
    // (donc identique partout).
    if ctx.downtime_enabled {
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

    // 0c. Libérer les unbondings mûrs.
    //
    // **Déterministe** : dépend uniquement de `ctx.current_time` (issu du
    // header du bloc, donc identique sur tous les nœuds) et de l'état.
    // Aucun flag nécessaire.
    //
    // Doit s'exécuter **avant** les transactions pour que les fonds
    // libérés soient disponibles dans le même bloc si un tx veut les
    // utiliser.
    if let Err(e) = crate::unbonding::process_matured_unbondings(state, ctx) {
        *state = snapshot;
        return Err(e);
    }

    // 1. Appliquer les transactions (sans toucher aux compteurs globaux).
    let mut applied: Vec<Applied> = Vec::with_capacity(validated.len());
    let mut total_gas_used: u64 = 0; // natif + EVM (pour le receipt)
    let mut total_gas_used_native: u64 = 0; // natif uniquement (pour NativeState)
    let mut total_fee: u128 = 0;
    let mut total_validator_fee: u128 = 0;
    let mut total_burned: u128 = 0;

    // `EvmBlockEnv` pour la totalité du bloc. Construit depuis le header.
    let evm_block_env = EvmBlockEnv {
        chain_id: ctx.evm_chain_id,
        number: block.header.height.get(),
        timestamp: block.header.timestamp,
        gas_limit: block.header.gas_limit,
        base_fee: U256::from(block.header.base_fee),
        coinbase: EvmAddress::ZERO,
        prevrandao: crate::derive_prevrandao(block.header.previous_block_hash),
        parent_block_hash: block.header.previous_block_hash,
    };

    for (tx, v) in block.transactions.iter().zip(validated.iter()) {
        match (tx, v) {
            (Tx::Native(native_tx), ValidatedTransaction::Native(vn)) => {
                let gas_used =
                    crate::staking::gas_for(native_tx.tx_kind).unwrap_or(NATIVE_TRANSFER_GAS);
                let a = match apply_tx_no_rollback(state, native_tx, vn, gas_used, ctx) {
                    Ok(a) => a,
                    Err(e) => {
                        *state = snapshot;
                        *evm_state = evm_snapshot;
                        return Err(e);
                    }
                };
                total_gas_used = total_gas_used
                    .checked_add(a.gas_used)
                    .ok_or(ApplyError::TotalGasUsedOverflow)?;
                total_gas_used_native = total_gas_used_native
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
                applied.push(Applied::Native(a));
            }
            (Tx::Evm(evm_tx), ValidatedTransaction::Evm(ve)) => {
                let extras = TxEnvExtras {
                    caller: ve.sender,
                    effective_gas_price: ve.effective_gas_price,
                };
                let outcome = match evm_transact(evm_state, evm_tx, &evm_block_env, extras) {
                    Ok(o) => o,
                    Err(e) => {
                        *state = snapshot;
                        *evm_state = evm_snapshot;
                        return Err(ApplyError::EvmExecution(e));
                    }
                };
                let total_fee_u256 = ve
                    .effective_gas_price
                    .saturating_mul(U256::from(outcome.gas_used));
                let total_fee_u128 = u256_to_u128_saturating(total_fee_u256);

                let a = AppliedEvmTx {
                    tx_hash: ve.tx_hash,
                    sender: ve.sender,
                    gas_used: outcome.gas_used,
                    effective_gas_price: ve.effective_gas_price,
                    total_fee: total_fee_u128,
                    logs: outcome.logs,
                    contract_address: outcome.contract_address,
                    output: outcome.output,
                    success: outcome.success,
                };

                total_gas_used = total_gas_used
                    .checked_add(a.gas_used)
                    .ok_or(ApplyError::TotalGasUsedOverflow)?;
                // NOTE : les fees EVM ne sont PAS reportées dans
                // `total_fee`, `total_validator_fee`, `total_burned` — ces
                // agrégats sont réservés aux effets Sango sur `NativeState`.
                // Les fees EVM sont débitées par revm dans `EvmState`.

                applied.push(Applied::Evm(a));
            }
            _ => {
                *state = snapshot;
                *evm_state = evm_snapshot;
                return Err(ApplyError::VariantMismatch);
            }
        }
    }

    // 2. Mettre à jour les compteurs globaux en une seule passe.
    if let Err(e) = state.add_burned(Amount::from_base_units(total_burned)) {
        *state = snapshot;
        *evm_state = evm_snapshot;
        return Err(ApplyError::State(e));
    }
    if let Err(e) = state.add_gas_used(total_gas_used_native) {
        *state = snapshot;
        *evm_state = evm_snapshot;
        return Err(ApplyError::State(e));
    }

    // 2bis. Distribuer les récompenses PoS au proposeur.
    //
    // Comme pour le downtime, ceci doit rester **désactivé** tant que la
    // distribution dépend de données locales (pool calculé localement,
    // participants locaux). Sinon chaque nœud distribue différemment et
    // les `state_root` divergent.
    let pos_rewards = if ctx.rewards_enabled {
        match crate::rewards::distribute_block_rewards(state, ctx.fee_recipient, ctx) {
            Ok(r) => r,
            Err(e) => {
                *state = snapshot;
                *evm_state = evm_snapshot;
                return Err(e);
            }
        }
    } else {
        None
    };

    // 3. Générer les receipts via `build_receipts`.
    //
    // Cette fonction est partagée avec le proposeur (voir
    // `Node::prepare_block_from_candidates`), ce qui garantit que les
    // deux chemins produisent exactement les mêmes receipts — donc le
    // même `receipt_root`.
    let receipts = build_receipts(&applied);

    // 4. Offre courante après application.
    let total_burned_after = state.total_burned();
    let current_supply =
        state
            .current_supply(ctx.initial_supply)
            .ok_or(ApplyError::CurrentSupplyUnderflow {
                initial: ctx.initial_supply.base_units(),
                burned: total_burned_after.base_units(),
            })?;

    // 5. Racine MPT Ethereum des transactions du bloc.
    //
    // Formule V1 (natif uniquement) : key_i = RLP(i),
    // value_i = canonical_sango_tx_bytes. L'ordre des txs est
    // consensus-critical, donc on l'itère tel quel.
    let transaction_root = compute_transaction_root(&block.transactions);

    // 6. Racine MPT Ethereum des receipts du bloc.
    //
    // Formule V1 : key_i = RLP(i), value_i = canonical_sango_receipt_bytes.
    let receipt_root = compute_receipt_root(&receipts);

    // 7. Racines d'état.
    //
    // `native_state_root` : SMT Sango (déjà disponible).
    // `evm_state_root`    : MPT Ethereum — vide en V1.
    // `state_root`        : combinaison Sango-specific définie dans
    //                       `sango_state::global_state_root`.
    let native_state_root = state.native_state_root();
    let evm_state_root = compute_evm_state_root(evm_state);
    let state_root = sango_state::global_state_root(native_state_root, evm_state_root);

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
        native_state_root,
        evm_state_root,
        state_root,
        transaction_root,
        receipt_root,
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
    validated: &ValidatedNativeTransaction,
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
    validated: &ValidatedNativeTransaction,
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

/// Sature une `U256` en `u128`.
#[must_use]
fn u256_to_u128_saturating(v: U256) -> u128 {
    if v > U256::from(u128::MAX) {
        u128::MAX
    } else {
        v.to::<u128>()
    }
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
    ) -> Result<ValidatedNativeTransaction, TxValidationError> {
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
            // Désactivés par défaut : c'est ce qui rend `apply_block`
            // déterministe dans le test multi-nœuds.
            rewards_enabled: false,
            downtime_enabled: false,
            evm_chain_id: DEFAULT_EVM_CHAIN_ID,
        }
    }

    /// Variante activant explicitement le suivi de participation
    /// (uniquement pour les tests unitaires).
    fn exec_ctx_with_downtime() -> ExecutionContext {
        ExecutionContext {
            downtime_enabled: true,
            ..exec_ctx()
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
            evidences: Vec::new(),
            transactions: Vec::new(),
        };
        let r = apply_block(
            &mut state,
            &mut sango_evm::EvmState::new(),
            &block,
            &[],
            &exec_ctx(),
            &[],
        )
        .unwrap();
        assert_eq!(r.apply_result.applied.len(), 0);
        assert_eq!(r.receipts.len(), 0);
        assert_eq!(r.gas_used, 0);
        assert_eq!(r.fee_burned, 0);
        assert_eq!(r.current_supply, exec_ctx().initial_supply);
        assert_eq!(r.total_burned_after, Amount::ZERO);
        assert_eq!(r.total_gas_used_after, 0);
        // Un bloc vide a pour `receipt_root` la racine MPT vide,
        // PAS `Hash32::ZERO`.
        assert_eq!(r.receipt_root, compute_receipt_root(&[]));
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
            evidences: Vec::new(),
            transactions: vec![Tx::Native(tx1.clone()), Tx::Native(tx2.clone())],
        };
        let r = apply_block(
            &mut state,
            &mut sango_evm::EvmState::new(),
            &block,
            &[
                ValidatedTransaction::Native(v1),
                ValidatedTransaction::Native(v2),
            ],
            &exec_ctx(),
            &[],
        )
        .unwrap();

        assert_eq!(r.receipts.len(), 2);
        assert_eq!(r.receipts[0].tx_hash, tx1.hash());
        assert_eq!(r.receipts[1].tx_hash, tx2.hash());
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
            evidences: Vec::new(),
            transactions: vec![Tx::Native(tx)],
        };
        let initial = exec_ctx().initial_supply;
        let r = apply_block(
            &mut state,
            &mut sango_evm::EvmState::new(),
            &block,
            &[ValidatedTransaction::Native(v)],
            &exec_ctx(),
            &[],
        )
        .unwrap();

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
            evidences: Vec::new(),
            transactions: vec![Tx::Native(tx1), Tx::Native(tx2)],
        };
        let err = apply_block(
            &mut state,
            &mut sango_evm::EvmState::new(),
            &block,
            &[
                ValidatedTransaction::Native(v1),
                ValidatedTransaction::Native(v2),
            ],
            &exec_ctx(),
            &[],
        )
        .unwrap_err();
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
            evidences: Vec::new(),
            transactions: Vec::new(),
        };
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let tx = bootstrap_tx(&kp, 0, 1);
        let _ = tx;
        let v = ValidatedTransaction::Native(ValidatedNativeTransaction {
            tx_hash: Hash32::ZERO,
            sender: NativeAddress::from_bytes([0xaa; 20]),
            effective_gas_price: 12,
            max_total_fee: 252_000,
            value: 100,
            bootstrap_public_key: None,
        });
        let err = apply_block(
            &mut state,
            &mut sango_evm::EvmState::new(),
            &block,
            &[v],
            &exec_ctx(),
            &[],
        )
        .unwrap_err();
        assert_eq!(
            err,
            ApplyError::LengthMismatch {
                txs: 0,
                validated: 1
            }
        );
    }

    #[test]
    fn empty_evm_state_root_is_mpt_empty_root() {
        assert_eq!(empty_evm_state_root(), sango_mpt::empty_root());
        // Pas d'ambiguïté : ce n'est PAS Hash32::ZERO.
        assert_ne!(empty_evm_state_root(), Hash32::ZERO);
        // `compute_evm_state_root` délègue à `EvmState::state_root()`.
        assert_eq!(
            compute_evm_state_root(&sango_evm::EvmState::new()),
            sango_mpt::empty_root()
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
            evidences: Vec::new(),
            transactions: vec![Tx::Native(tx)],
        };
        let r = apply_block(
            &mut state,
            &mut sango_evm::EvmState::new(),
            &block,
            &[ValidatedTransaction::Native(v)],
            &exec_ctx(),
            &[],
        )
        .unwrap();

        assert_eq!(r.native_state_root, state.native_state_root());
        assert_eq!(r.evm_state_root, empty_evm_state_root());
        assert_eq!(
            r.state_root,
            sango_state::global_state_root(r.native_state_root, r.evm_state_root)
        );
    }

    #[test]
    fn apply_block_integrated_downtime() {
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

        let mut h = sample_header();
        h.height = sango_primitives::Height::new(1);
        let block = Block {
            header: h,
            evidences: Vec::new(),
            transactions: Vec::new(),
        };

        let ctx = exec_ctx_with_downtime();
        apply_block(
            &mut state,
            &mut sango_evm::EvmState::new(),
            &block,
            &[],
            &ctx,
            &[a],
        )
        .unwrap();

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
            evidences: Vec::new(),
            transactions: Vec::new(),
        };
        let ctx = exec_ctx_with_downtime();
        apply_block(
            &mut state,
            &mut sango_evm::EvmState::new(),
            &block,
            &[],
            &ctx,
            &[],
        )
        .unwrap();

        assert_eq!(state.get_validator(&addr).unwrap().downtime_missed, 1);
    }

    /// Vérifie explicitement le déterminisme.
    ///
    /// Deux `apply_block` sur le même bloc, avec les flags par défaut
    /// (`downtime_enabled == false`, `rewards_enabled == false`),
    /// produisent **exactement** le même `native_state_root`.
    #[test]
    fn apply_block_is_deterministic_with_defaults() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let sender = derive_native_address(&kp.public_key());

        let mk_state = || {
            let mut s = NativeState::new();
            s.credit(sender, Amount::from_base_units(1_000_000))
                .unwrap();
            s
        };

        let mut state_a = mk_state();
        let mut state_b = mk_state();

        let tx = bootstrap_tx(&kp, 0, 100);
        let v = validate(&state_a, &tx).unwrap();
        let block = Block {
            header: sample_header(),
            evidences: Vec::new(),
            transactions: vec![Tx::Native(tx)],
        };

        // Variante A : participants = [sender].
        let ra = apply_block(
            &mut state_a,
            &mut sango_evm::EvmState::new(),
            &block,
            &[ValidatedTransaction::Native(v.clone())],
            &exec_ctx(),
            &[sender],
        )
        .unwrap();

        // Variante B : participants = [] (comme si un autre nœud avait vu
        // un `CommitCertificate` différent). Doit donner le **même** root,
        // car le downtime est désactivé.
        let rb = apply_block(
            &mut state_b,
            &mut sango_evm::EvmState::new(),
            &block,
            &[ValidatedTransaction::Native(v)],
            &exec_ctx(),
            &[],
        )
        .unwrap();

        assert_eq!(
            ra.native_state_root, rb.native_state_root,
            "avec downtime désactivé, les participants ne doivent PAS influencer le root"
        );
    }
}
