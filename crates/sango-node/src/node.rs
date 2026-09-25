//! Nœud Sango : orchestration validation → application → persistance.

use std::path::Path;

use sango_codec::{Decode, Encode};
use sango_evm::{evm_transact, EvmBlockEnv, EvmOutcome, EvmState, TxEnvExtras};
use sango_exec::{
    apply_block as exec_apply_block, BlockExecutionResult, ExecutionContext,
    ValidatedEvmTransaction, ValidatedTransaction,
};
use sango_primitives::{
    Amount, ChainId32, Epoch, EvmAddress, Hash32, Height, NativeAddress, Round, U256,
};
use sango_state::{MetadataKey, NativeState};
use sango_storage::{metadata_key, Batch, Column, Storage};
use sango_tx::{validate_transaction, SenderInfo, ValidationContext};
use sango_types::{Block, BlockHeader, ChainTip, Tx};

use crate::base_fee::{next_base_fee, INITIAL_BASE_FEE};
use crate::diff::{diff_evm, diff_state, EvmDiff};
use crate::error::NodeError;

/// Nœud Sango.
pub struct Node {
    storage: Storage,
    state: NativeState,
    /// État EVM (accounts + storage + code).
    ///
    /// En V1, aucun bloc ne contient encore de transaction EVM exécutée,
    /// donc cet état reste vide. Il est exposé aux RPC `eth_*` (lecture)
    /// et sera peuplé en 4c.3 quand EVM sera branché dans `apply_block`.
    evm: EvmState,
    chain_id: ChainId32,
    /// Chain ID EVM (`u64`), pour les RPC `eth_*` et le bridge revm.
    ///
    /// Valeur par défaut : `0x53414e47_4f` (« SANGO » en ASCII).
    evm_chain_id: u64,
    initial_supply: Amount,
    tip: Option<ChainTip>,
    rewards_enabled: bool,
}

impl Node {
    /// Ouvre (ou crée) un nœud à l'emplacement `path`.
    pub fn open(
        path: impl AsRef<Path>,
        chain_id: ChainId32,
        initial_supply: Amount,
    ) -> Result<Self, NodeError> {
        let storage = Storage::open(path)?;
        let mut state = NativeState::new();

        for (key_bytes, value) in storage.iter_column(Column::StateNative)? {
            if key_bytes.len() != 32 {
                return Err(NodeError::CorruptedStateKey {
                    got: key_bytes.len(),
                });
            }
            let mut raw = [0u8; 32];
            raw.copy_from_slice(&key_bytes);
            state.restore_entry(Hash32::from_bytes(raw), value);
        }

        if let Some(total_burned) = storage.get_total_burned()? {
            state
                .add_burned(total_burned)
                .map_err(sango_exec::ApplyError::from)?;
        }
        if let Some(total_gas_used) = storage.get_total_gas_used()? {
            state
                .add_gas_used(total_gas_used)
                .map_err(sango_exec::ApplyError::from)?;
        }

        let tip = storage.get_chain_tip()?;

        // --- Restauration de l'EvmState ---
        let mut evm = EvmState::new();

        for (key_bytes, value) in storage.iter_column(Column::EvmAccounts)? {
            if key_bytes.len() != 32 {
                return Err(NodeError::CorruptedStateKey {
                    got: key_bytes.len(),
                });
            }
            let mut raw = [0u8; 32];
            raw.copy_from_slice(&key_bytes);
            evm.restore_account_entry(Hash32::from_bytes(raw), value);
        }

        for (key_bytes, value) in storage.iter_column(Column::EvmStorage)? {
            if key_bytes.len() != 52 {
                return Err(NodeError::CorruptedStateKey {
                    got: key_bytes.len(),
                });
            }
            let mut addr_raw = [0u8; 20];
            addr_raw.copy_from_slice(&key_bytes[..20]);
            let mut slot_raw = [0u8; 32];
            slot_raw.copy_from_slice(&key_bytes[20..]);
            evm.restore_storage_entry(
                EvmAddress::from_bytes(addr_raw),
                Hash32::from_bytes(slot_raw),
                value,
            );
        }

        for (key_bytes, value) in storage.iter_column(Column::EvmCode)? {
            if key_bytes.len() != 32 {
                return Err(NodeError::CorruptedStateKey {
                    got: key_bytes.len(),
                });
            }
            let mut raw = [0u8; 32];
            raw.copy_from_slice(&key_bytes);
            evm.restore_code_entry(Hash32::from_bytes(raw), value)
                .map_err(NodeError::Evm)?;
        }

        Ok(Self {
            storage,
            state,
            evm,
            chain_id,
            evm_chain_id: DEFAULT_EVM_CHAIN_ID,
            initial_supply,
            tip,
            rewards_enabled: false,
        })
    }

    /// Ouvre un nœud avec distribution PoS activée.
    ///
    /// Utilisé en production/testnet/mainnet après activation du pool
    /// par le Genesis.
    pub fn open_with_rewards(
        path: impl AsRef<Path>,
        chain_id: ChainId32,
        initial_supply: Amount,
    ) -> Result<Self, NodeError> {
        let mut node = Self::open(path, chain_id, initial_supply)?;
        node.rewards_enabled = true;
        Ok(node)
    }

    /// Vue en lecture sur l'état.
    #[must_use]
    pub fn state(&self) -> &NativeState {
        &self.state
    }

    /// Vue en écriture sur l'état. **Usage tests uniquement** : ne pas
    /// appeler depuis du code de production, qui doit passer par
    /// `apply_block`.
    #[doc(hidden)]
    pub fn state_mut_for_test(&mut self) -> &mut NativeState {
        &mut self.state
    }

    /// Vue en lecture sur le stockage.
    #[must_use]
    pub fn storage(&self) -> &Storage {
        &self.storage
    }

    /// Chain ID natif du réseau.
    #[must_use]
    pub fn chain_id(&self) -> ChainId32 {
        self.chain_id
    }

    /// Offre initiale.
    #[must_use]
    pub fn initial_supply(&self) -> Amount {
        self.initial_supply
    }

    /// Tip courant (dernier bloc appliqué), si présent.
    #[must_use]
    pub fn tip(&self) -> Option<ChainTip> {
        self.tip
    }

    /// Base fee attendue pour un bloc candidat.
    ///
    /// - Si aucun tip : [`INITIAL_BASE_FEE`].
    /// - Sinon : calcul EIP-1559 à partir du header du parent.
    pub fn expected_base_fee(&self) -> Result<u128, NodeError> {
        match self.tip {
            None => Ok(INITIAL_BASE_FEE),
            Some(tip) => {
                let parent = self.load_header(&tip.block_hash)?;
                Ok(next_base_fee(&parent))
            }
        }
    }

    /// Charge un header depuis RocksDB par hash.
    fn load_header(&self, hash: &Hash32) -> Result<BlockHeader, NodeError> {
        let bytes = self
            .storage
            .get(Column::BlockHeaders, hash.as_bytes())?
            .ok_or(NodeError::ParentHeaderNotFound { hash: *hash })?;
        BlockHeader::decode_exact(&bytes)
            .map_err(|e| NodeError::Storage(sango_storage::StorageError::Codec(e)))
    }

    /// Construit un [`SenderInfo`] depuis un état donné.
    fn sender_info_from_state(state: &NativeState, address: NativeAddress) -> SenderInfo {
        match state.get_account(&address) {
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
            None => SenderInfo::ghost(address, 0, 0),
        }
    }

    /// Construit un [`SenderInfo`] à partir de l'état courant.
    fn sender_info(&self, address: NativeAddress) -> SenderInfo {
        Self::sender_info_from_state(&self.state, address)
    }

    /// Prépare un bloc à proposer à partir d'une liste ordonnée de
    /// transactions candidates (typiquement issues du mempool).
    ///
    /// ## Comportement
    ///
    /// 1. **Pré-filtrage** tx par tx sur un clone jetable de l'état : ne
    ///    garde que celles qui passent validation + application.
    /// 2. **Simulation** complète du bloc candidat via `apply_block` sur
    ///    un **second** clone jetable. Cela donne les vraies roots
    ///    (`transaction_root`, `receipt_root`, `state_root`) calculées
    ///    exactement comme le fera le validateur.
    /// 3. **Construction** du header final avec ces roots.
    ///
    /// ## Roots V1
    ///
    /// - `transaction_root` : MPT Ethereum-compatible
    ///   (`RLP(i) → canonical_sango_tx_bytes`).
    /// - `receipt_root` : MPT Ethereum-compatible
    ///   (`RLP(i) → canonical_sango_receipt_bytes`).
    /// - `state_root` : `Keccak256("SANGO/STATE/ROOT/V1" || native || evm)`
    ///   avec `evm_state_root = empty_evm_state_root()` en V1.
    ///
    /// Le `Vec<ValidatedTransaction>` retourné correspond 1:1 aux txs du
    /// bloc, dans le même ordre.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_block_from_candidates(
        &self,
        epoch: Epoch,
        round: Round,
        candidates: Vec<Tx>,
        max_txs: usize,
        proposer: NativeAddress,
        timestamp: u64,
        evidences: Vec<sango_types::Evidence>,
    ) -> (Block, Vec<ValidatedTransaction>) {
        use sango_exec::{apply_tx_no_rollback, gas_for, ExecutionContext, NATIVE_TRANSFER_GAS};

        // ------------------------------------------------------------------
        // Phase 1 — pré-filtrage tx par tx.
        // ------------------------------------------------------------------
        let (parent_hash, height) = match self.tip {
            Some(t) => (t.block_hash, t.height.get() + 1),
            None => (Hash32::ZERO, 0),
        };
        let base_fee = self
            .expected_base_fee()
            .unwrap_or(crate::base_fee::INITIAL_BASE_FEE);

        let mut trial_filter = self.state.clone();
        let mut trial_evm = self.evm.clone();
        let mut accepted: Vec<Tx> = Vec::new();
        let mut validated: Vec<ValidatedTransaction> = Vec::new();

        // `EvmBlockEnv` commun à la pré-validation (phase 1) et à la
        // simulation complète (phase 2). Doit être identique, sinon
        // divergence du résultat revm.
        let evm_block_env = EvmBlockEnv {
            chain_id: self.evm_chain_id,
            number: height,
            timestamp,
            gas_limit: 30_000_000,
            base_fee: U256::from(base_fee),
            coinbase: EvmAddress::ZERO,
            prevrandao: sango_exec::derive_prevrandao(parent_hash),
            parent_block_hash: parent_hash,
        };

        for tx in candidates.into_iter().take(max_txs) {
            match tx {
                Tx::Native(native) => {
                    let sender = Self::sender_info_from_state(&trial_filter, native.sender);
                    let vctx = ValidationContext {
                        expected_chain_id: self.chain_id,
                        base_fee,
                        sender: &sender,
                    };
                    let vn = match validate_transaction(&native, &vctx) {
                        Ok(v) => v,
                        Err(_) => break,
                    };
                    let gas_used = gas_for(native.tx_kind).unwrap_or(NATIVE_TRANSFER_GAS);
                    let exec_ctx = ExecutionContext {
                        chain_id: self.chain_id,
                        base_fee,
                        fee_recipient: proposer,
                        initial_supply: self.initial_supply,
                        current_time: timestamp,
                        current_height: height,
                        rewards_enabled: self.rewards_enabled,
                        downtime_enabled: false,
                        evm_chain_id: self.evm_chain_id,
                    };
                    if apply_tx_no_rollback(&mut trial_filter, &native, &vn, gas_used, &exec_ctx)
                        .is_err()
                    {
                        break;
                    }
                    accepted.push(Tx::Native(native));
                    validated.push(ValidatedTransaction::Native(vn));
                }
                Tx::Evm(evm) => {
                    let ve = match self.validate_evm_tx(&evm, base_fee) {
                        Ok(v) => v,
                        Err(_) => break,
                    };
                    let extras = TxEnvExtras {
                        caller: ve.sender,
                        effective_gas_price: ve.effective_gas_price,
                    };
                    // Un REVERT/HALT renvoie `Ok(outcome)` — on accepte la
                    // tx (elle consomme du gas et laisse une trace). Un
                    // `Err` (nonce invalide, fonds insuffisants…) rejette.
                    if evm_transact(&mut trial_evm, &evm, &evm_block_env, extras).is_err() {
                        break;
                    }
                    accepted.push(Tx::Evm(evm));
                    validated.push(ValidatedTransaction::Evm(ve));
                }
            }
        }

        // ------------------------------------------------------------------
        // Phase 2 — simulation complète via `apply_block` sur trial.
        //
        // Le header préliminaire n'est **pas** lu par `apply_block` (les
        // roots ne sont utilisées ni en entrée ni en vérification pendant
        // l'exécution). On met des valeurs nulles par sécurité.
        //
        // En V1, `downtime_enabled = false` → `participants` n'est pas lu.
        // On passe un slice vide pour rester cohérent avec le chemin de
        // validation (`apply_block` appelé avec `&[]` dans les tests).
        // ------------------------------------------------------------------
        let prelim_header = BlockHeader {
            version: sango_types::PROTOCOL_VERSION_V1,
            chain_id: self.chain_id,
            epoch,
            height: Height::new(height),
            round,
            previous_block_hash: parent_hash,
            timestamp,
            proposer_address: proposer,
            transaction_root: Hash32::ZERO,
            state_root: Hash32::ZERO,
            receipt_root: Hash32::ZERO,
            gas_used: 0,
            gas_limit: 30_000_000,
            base_fee,
        };
        let prelim_block = Block {
            header: prelim_header,
            evidences: evidences.clone(),
            transactions: accepted.clone(),
        };

        let mut trial_sim = self.state.clone();
        let mut trial_evm = self.evm.clone();
        let sim_ctx = ExecutionContext {
            chain_id: self.chain_id,
            base_fee,
            fee_recipient: proposer,
            initial_supply: self.initial_supply,
            current_time: timestamp,
            current_height: height,
            rewards_enabled: self.rewards_enabled,
            downtime_enabled: false,
            evm_chain_id: self.evm_chain_id,
        };
        let sim_result = exec_apply_block(
            &mut trial_sim,
            &mut trial_evm,
            &prelim_block,
            &validated,
            &sim_ctx,
            &[],
        )
        .expect("block simulation must succeed (txs were pre-filtered)");

        // ------------------------------------------------------------------
        // Phase 3 — header final avec les roots calculées par la simulation.
        // ------------------------------------------------------------------
        let final_header = BlockHeader {
            version: sango_types::PROTOCOL_VERSION_V1,
            chain_id: self.chain_id,
            epoch,
            height: Height::new(height),
            round,
            previous_block_hash: parent_hash,
            timestamp,
            proposer_address: proposer,
            transaction_root: sim_result.transaction_root,
            state_root: sim_result.state_root,
            receipt_root: sim_result.receipt_root,
            gas_used: sim_result.gas_used,
            gas_limit: 30_000_000,
            base_fee,
        };
        let final_block = Block {
            header: final_header,
            evidences,
            transactions: accepted,
        };
        (final_block, validated)
    }

    /// Lit un bloc par hauteur.
    ///
    /// Retourne `None` si aucun bloc n'est enregistré à cette hauteur.
    pub fn get_block_by_height(&self, height: u64) -> Result<Option<Block>, NodeError> {
        let height_key = height.to_le_bytes();
        let Some(hash_bytes) = self.storage.get(Column::BlockHeights, &height_key)? else {
            return Ok(None);
        };
        if hash_bytes.len() != 32 {
            return Err(NodeError::CorruptedStateKey {
                got: hash_bytes.len(),
            });
        }
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&hash_bytes);
        let hash = Hash32::from_bytes(raw);
        let Some(block_bytes) = self.storage.get(Column::Blocks, hash.as_bytes())? else {
            return Ok(None);
        };
        Block::decode_exact(&block_bytes)
            .map(Some)
            .map_err(|e| NodeError::Storage(sango_storage::StorageError::Codec(e)))
    }

    /// Liste tous les validateurs enregistrés.
    #[must_use]
    pub fn all_validators(&self) -> Vec<sango_types::ValidatorInfo> {
        use sango_state::{state_key_hash, Namespace};
        let mut out = Vec::new();
        for (key_hash, value) in self.state.iter_entries() {
            if let Ok(info) = sango_types::ValidatorInfo::decode_exact(value) {
                let expected = state_key_hash(Namespace::Validator, info.address.as_bytes());
                if expected == *key_hash {
                    out.push(info);
                }
            }
        }
        out
    }

    /// Initialise l'état à partir d'un Genesis (comptes + validateurs).
    pub fn initialize_genesis(
        &mut self,
        accounts: &[sango_types::NativeAccount],
        validators: &[sango_types::ValidatorInfo],
    ) -> Result<(), NodeError> {
        if self.tip.is_some() {
            return Err(NodeError::AlreadyInitialized);
        }

        let mut trial = self.state.clone();
        for account in accounts {
            trial.set_account(*account);
        }
        for v in validators {
            trial.set_validator(*v);
        }

        let diff = diff_state(&self.state, &trial);
        let mut batch = Batch::new();
        for (k, v) in &diff.inserts {
            batch.put(Column::StateNative, k.as_bytes(), v.clone());
        }
        for (k, v) in &diff.updates {
            batch.put(Column::StateNative, k.as_bytes(), v.clone());
        }
        for k in &diff.deletes {
            batch.delete(Column::StateNative, k.as_bytes());
        }

        if let Err(e) = self.storage.write_batch(batch) {
            return Err(NodeError::Storage(e));
        }
        if let Err(e) = self.storage.flush() {
            return Err(NodeError::Storage(e));
        }

        self.state = trial;
        Ok(())
    }

    /// Valide une transaction EVM de manière **consensus minimale**.
    ///
    /// ## Contrat 4c.3.3
    ///
    /// Seuls ces checks sont faits **avant** `evm_transact` :
    ///
    /// 1. `chain_id` de la tx = `self.evm_chain_id` ;
    /// 2. signature secp256k1 récupérable → `sender` ;
    /// 3. `max_fee_per_gas >= base_fee` (sinon rejet immédiat) ;
    ///
    /// Le reste (nonce, balance, gas, code, storage…) est **rejeté ou
    /// accepté par revm** lors de `evm_transact`. Ceci évite de dupliquer
    /// la logique Ethereum dans Sango.
    fn validate_evm_tx(
        &self,
        evm_tx: &sango_types::EvmTx,
        base_fee: u128,
    ) -> Result<ValidatedEvmTransaction, String> {
        // (1) chain_id.
        let tx_chain_id = match evm_tx {
            sango_types::EvmTx::Legacy { chain_id, .. }
            | sango_types::EvmTx::Eip2930 { chain_id, .. }
            | sango_types::EvmTx::Eip1559 { chain_id, .. }
            | sango_types::EvmTx::Eip7702 { chain_id, .. } => *chain_id,
        };
        if tx_chain_id != self.evm_chain_id {
            return Err(format!(
                "chain_id mismatch: expected {}, got {}",
                self.evm_chain_id, tx_chain_id
            ));
        }

        // (2) Recovery du sender.
        let sender =
            sango_evm::recover_sender(evm_tx).map_err(|_| "invalid signature".to_string())?;

        // (3) Fee minimale.
        let max_fee = sango_evm::max_fee_per_gas(evm_tx);
        let base_fee_u256 = U256::from(base_fee);
        if max_fee < base_fee_u256 {
            return Err("max_fee_per_gas < base_fee".to_string());
        }

        // (4) Prix effectif (règle Sango unifiée).
        let effective_gas_price = sango_exec::effective_gas_price(
            max_fee,
            sango_evm::max_priority_fee(evm_tx),
            base_fee_u256,
        )
        .map_err(|e| format!("effective_gas_price: {e}"))?;

        Ok(ValidatedEvmTransaction {
            tx_hash: self.evm_tx_hash(evm_tx),
            sender,
            effective_gas_price,
        })
    }

    /// Hash canonique d'une tx EVM : `Keccak256(typed_tx_bytes)`.
    fn evm_tx_hash(&self, evm_tx: &sango_types::EvmTx) -> Hash32 {
        sango_crypto::keccak256(&evm_tx.encode_ethereum_typed())
    }

    /// Applique un bloc de bout en bout.
    ///
    /// ## Vérifications
    ///
    /// 1. `chain_id` du header correspond au nœud.
    /// 2. `previous_block_hash` correspond au tip (ou `ZERO` si vierge).
    /// 3. `height` vaut `tip.height + 1` (ou `0`/`1` si vierge).
    /// 4. `base_fee` correspond au calcul EIP-1559.
    /// 5. `transaction_root` correspond au recalcul local via MPT
    ///    Ethereum-compatible.
    /// 6. `receipt_root` correspond au recalcul local via MPT
    ///    Ethereum-compatible à partir des receipts d'exécution.
    /// 7. `state_root` correspond au recalcul local
    ///    `Keccak256("SANGO/STATE/ROOT/V1" || native || evm)` avec
    ///    `evm_state_root = empty_evm_state_root()` en V1.
    /// 8. Chaque transaction est validée.
    pub fn apply_block(
        &mut self,
        block: &Block,
        participants: &[NativeAddress],
    ) -> Result<BlockExecutionResult, NodeError> {
        // (0) Guard d'idempotence.
        let block_hash = block.hash();
        if let Some(tip) = self.tip {
            if tip.block_hash == block_hash {
                return Err(NodeError::AlreadyApplied { hash: block_hash });
            }
        }

        // (1) chain_id.
        if block.header.chain_id != self.chain_id {
            return Err(NodeError::ChainIdMismatch);
        }

        // (2) parent_hash + height.
        let (expected_parent, expected_height, expected_base_fee) = match self.tip {
            None => (Hash32::ZERO, 0u64, INITIAL_BASE_FEE),
            Some(tip) => {
                let parent = self.load_header(&tip.block_hash)?;
                (tip.block_hash, tip.height.get() + 1, next_base_fee(&parent))
            }
        };
        if block.header.previous_block_hash != expected_parent {
            return Err(NodeError::ParentHashMismatch {
                expected: expected_parent,
                got: block.header.previous_block_hash,
            });
        }
        if block.header.height.get() != expected_height {
            return Err(NodeError::HeightMismatch {
                expected: expected_height,
                got: block.header.height.get(),
            });
        }

        // (3) base_fee.
        if block.header.base_fee != expected_base_fee {
            return Err(NodeError::BaseFeeMismatch {
                expected: expected_base_fee,
                got: block.header.base_fee,
            });
        }

        // (3b) `transaction_root`.
        let computed_tx_root = sango_exec::compute_transaction_root(&block.transactions);
        if computed_tx_root != block.header.transaction_root {
            return Err(NodeError::TransactionRootMismatch {
                expected: computed_tx_root,
                got: block.header.transaction_root,
            });
        }

        // (4) Validation par transaction.
        //
        // 4c.3.3 : natifs validés via `sango-tx`, EVM via recovery de
        // signature + checks consensus minimaux (revm reste l'autorité
        // d'exécution pour le reste : balance, nonce, gas…).
        let mut validated: Vec<ValidatedTransaction> = Vec::with_capacity(block.transactions.len());
        for (index, tx) in block.transactions.iter().enumerate() {
            match tx {
                Tx::Native(native) => {
                    let sender = self.sender_info(native.sender);
                    let vctx = ValidationContext {
                        expected_chain_id: self.chain_id,
                        base_fee: block.header.base_fee,
                        sender: &sender,
                    };
                    let v = validate_transaction(native, &vctx)
                        .map_err(|e| NodeError::Validation { index, source: e })?;
                    validated.push(ValidatedTransaction::Native(v));
                }
                Tx::Evm(evm) => {
                    let v = self
                        .validate_evm_tx(evm, block.header.base_fee)
                        .map_err(|reason| NodeError::EvmValidation { index, reason })?;
                    validated.push(ValidatedTransaction::Evm(v));
                }
            }
        }

        // (5) Snapshot + application.
        let state_before = self.state.clone();
        let evm_before = self.evm.clone();
        let ctx = ExecutionContext {
            chain_id: self.chain_id,
            base_fee: block.header.base_fee,
            fee_recipient: block.header.proposer_address,
            initial_supply: self.initial_supply,
            current_time: block.header.timestamp,
            current_height: block.header.height.get(),
            rewards_enabled: self.rewards_enabled,
            downtime_enabled: false,
            evm_chain_id: self.evm_chain_id,
        };
        let result = exec_apply_block(
            &mut self.state,
            &mut self.evm,
            block,
            &validated,
            &ctx,
            participants,
        )?;

        // (5b) Vérification du `receipt_root`.
        if result.receipt_root != block.header.receipt_root {
            self.state = state_before;
            self.evm = evm_before;
            return Err(NodeError::ReceiptRootMismatch {
                expected: result.receipt_root,
                got: block.header.receipt_root,
            });
        }

        // (5c) Vérification du `state_root` global.
        //
        // `state_root = Keccak256("SANGO/STATE/ROOT/V1" || native || evm)`.
        // En V1 : `evm_state_root = empty_evm_state_root()`.
        if result.state_root != block.header.state_root {
            self.state = state_before;
            self.evm = evm_before;
            return Err(NodeError::StateRootMismatch {
                expected: result.state_root,
                got: block.header.state_root,
            });
        }

        // (6) Diff natif.
        let diff = diff_state(&state_before, &self.state);

        // (6b) Diff EVM.
        let evm_diff = diff_evm(&evm_before, &self.evm);

        // (7) Batch.
        let mut batch = Batch::new();
        batch.put(Column::Blocks, block_hash.as_bytes(), block.encode_to_vec());
        batch.put(
            Column::BlockHeaders,
            block_hash.as_bytes(),
            block.header.encode_to_vec(),
        );
        batch.put(
            Column::BlockHeights,
            block.header.height.get().to_le_bytes(),
            block_hash.as_bytes(),
        );
        for tx in &block.transactions {
            let tx_hash = tx.hash();
            batch.put(Column::Transactions, tx_hash.as_bytes(), tx.encode_to_vec());
        }
        for receipt in &result.receipts {
            batch.put(
                Column::Receipts,
                receipt.tx_hash.as_bytes(),
                receipt.encode_to_vec(),
            );
        }
        for (k, v) in &diff.inserts {
            batch.put(Column::StateNative, k.as_bytes(), v.clone());
        }
        for (k, v) in &diff.updates {
            batch.put(Column::StateNative, k.as_bytes(), v.clone());
        }
        for k in &diff.deletes {
            batch.delete(Column::StateNative, k.as_bytes());
        }
        add_evm_diff_to_batch(&mut batch, &evm_diff);
        batch.put(
            Column::Metadata,
            metadata_key(MetadataKey::TotalBurned),
            result.total_burned_after.base_units().encode_to_vec(),
        );
        batch.put(
            Column::Metadata,
            metadata_key(MetadataKey::TotalGasUsed),
            result.total_gas_used_after.encode_to_vec(),
        );

        let new_tip = ChainTip {
            height: block.header.height,
            block_hash,
            base_fee: block.header.base_fee,
        };
        batch.put(
            Column::Metadata,
            metadata_key(MetadataKey::ChainTip),
            new_tip.encode_to_vec(),
        );

        // (8) Persistance.
        if let Err(e) = self.storage.write_batch(batch) {
            self.state = state_before;
            return Err(NodeError::Storage(e));
        }
        if let Err(e) = self.storage.flush() {
            self.state = state_before;
            return Err(NodeError::Storage(e));
        }

        // (9) Tip.
        self.tip = Some(new_tip);

        Ok(result)
    }
}

/// Ajoute les écritures EVM d'un diff à un `Batch` existant.
///
/// ## Format des clés
///
/// - `EvmAccounts` : `keccak256(evm_addr)` (32 bytes)
/// - `EvmStorage`  : `evm_addr(20) || slot_hash(32)` (52 bytes)
/// - `EvmCode`     : `code_hash` (32 bytes)
fn add_evm_diff_to_batch(batch: &mut Batch, diff: &EvmDiff) {
    for (k, v) in &diff.account_inserts {
        batch.put(Column::EvmAccounts, k.as_bytes(), v.clone());
    }
    for (k, v) in &diff.account_updates {
        batch.put(Column::EvmAccounts, k.as_bytes(), v.clone());
    }
    for k in &diff.account_deletes {
        batch.delete(Column::EvmAccounts, k.as_bytes());
    }

    // Storage : clé composite 20 || 32.
    let storage_key = |addr: &EvmAddress, slot: &Hash32| -> [u8; 52] {
        let mut k = [0u8; 52];
        k[..20].copy_from_slice(addr.as_bytes());
        k[20..].copy_from_slice(slot.as_bytes());
        k
    };
    for (addr, slot, v) in &diff.storage_inserts {
        batch.put(Column::EvmStorage, storage_key(addr, slot), v.clone());
    }
    for (addr, slot, v) in &diff.storage_updates {
        batch.put(Column::EvmStorage, storage_key(addr, slot), v.clone());
    }
    for (addr, slot) in &diff.storage_deletes {
        batch.delete(Column::EvmStorage, storage_key(addr, slot));
    }

    for (ch, bytecode) in &diff.code_inserts {
        batch.put(Column::EvmCode, ch.as_bytes(), bytecode.clone());
    }
}

/// Chain ID EVM par défaut (« SANGO » en ASCII).
pub const DEFAULT_EVM_CHAIN_ID: u64 = 0x53_41_4e_47_4f;

impl Node {
    // --- EVM --------------------------------------------------------------

    /// Vue en lecture sur l'état EVM.
    #[must_use]
    pub fn evm(&self) -> &EvmState {
        &self.evm
    }

    /// Vue en écriture sur l'état EVM. **Usage tests uniquement**.
    #[doc(hidden)]
    pub fn evm_mut_for_test(&mut self) -> &mut EvmState {
        &mut self.evm
    }

    /// Chain ID EVM.
    #[must_use]
    pub fn evm_chain_id(&self) -> u64 {
        self.evm_chain_id
    }

    /// Force le chain ID EVM (appelé depuis `main.rs` après chargement du
    /// Genesis).
    pub fn set_evm_chain_id(&mut self, id: u64) {
        self.evm_chain_id = id;
    }

    /// **Tests uniquement** : persiste l'état EVM courant comme un diff
    /// complet depuis un état vide.
    ///
    /// En production, `apply_block` écrit un **diff** incrémental via
    /// [`add_evm_diff_to_batch`]. Cette méthode existe pour tester la
    /// restauration RocksDB sans avoir à construire un bloc contenant des
    /// transactions EVM.
    #[doc(hidden)]
    pub fn persist_evm_full_for_test(&mut self) -> Result<(), NodeError> {
        let diff = diff_evm(&EvmState::new(), &self.evm);
        let mut batch = Batch::new();
        add_evm_diff_to_batch(&mut batch, &diff);
        self.storage.write_batch(batch)?;
        self.storage.flush()?;
        Ok(())
    }

    /// Solde EVM d'une adresse.
    #[must_use]
    pub fn evm_get_balance(&self, addr: &EvmAddress) -> U256 {
        self.evm.get_account(addr).map_or(U256::ZERO, |a| a.balance)
    }

    /// Nonce EVM d'une adresse.
    #[must_use]
    pub fn evm_get_nonce(&self, addr: &EvmAddress) -> u64 {
        self.evm.get_account(addr).map_or(0, |a| a.nonce)
    }

    /// Bytecode EVM d'un compte.
    #[must_use]
    pub fn evm_get_code(&self, addr: &EvmAddress) -> Vec<u8> {
        match self.evm.get_account(addr) {
            Some(acc) => self
                .evm
                .get_code(&acc.code_hash)
                .map(|s| s.to_vec())
                .unwrap_or_default(),
            None => Vec::new(),
        }
    }

    /// Valeur d'un slot de storage EVM.
    #[must_use]
    pub fn evm_get_storage(&self, addr: &EvmAddress, slot: U256) -> U256 {
        self.evm.get_storage(addr, slot)
    }

    /// Construit un `EvmBlockEnv` pour simuler la **prochaine** hauteur.
    ///
    /// Utilise `tip` (si présent) comme parent :
    /// - `number = tip.height + 1` ;
    /// - `timestamp = parent.timestamp + 1` ;
    /// - `base_fee = next_base_fee(parent)` ;
    /// - `prevrandao = derive_prevrandao(tip.block_hash)`.
    pub fn evm_block_env(&self) -> Result<EvmBlockEnv, NodeError> {
        let (number, timestamp, base_fee_u128, parent_hash) = match self.tip {
            Some(t) => {
                let parent = self.load_header(&t.block_hash)?;
                (
                    t.height.get() + 1,
                    parent.timestamp.saturating_add(1),
                    next_base_fee(&parent),
                    t.block_hash,
                )
            }
            None => (0, 1_700_000_000u64, INITIAL_BASE_FEE, Hash32::ZERO),
        };
        Ok(EvmBlockEnv {
            chain_id: self.evm_chain_id,
            number,
            timestamp,
            gas_limit: sango_types::EVM_GAS_LIMIT,
            base_fee: U256::from(base_fee_u128),
            coinbase: EvmAddress::ZERO,
            prevrandao: sango_exec::derive_prevrandao(parent_hash),
            parent_block_hash: parent_hash,
        })
    }

    /// Exécution EVM read-only (`eth_call`).
    ///
    /// Clone `self.evm`, exécute la transaction, retourne le résultat —
    /// **l'état n'est pas modifié**. Utilisé par `NodeBackend::eth_call`.
    pub fn evm_call_readonly(
        &self,
        req: &sango_rpc::EthCallRequest,
    ) -> Result<EvmOutcome, NodeError> {
        let block_env = self.evm_block_env()?;
        let effective_gas_price = req.gas_price.unwrap_or(block_env.base_fee);
        let gas_limit = req.gas.unwrap_or(sango_types::EVM_GAS_LIMIT);
        let nonce = self.evm_get_nonce(&req.from);

        let tx = sango_types::EvmTx::Legacy {
            chain_id: block_env.chain_id,
            nonce,
            gas_price: effective_gas_price,
            gas_limit,
            to: req.to,
            value: req.value,
            data: req.data.clone(),
            y_parity: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };

        let extras = TxEnvExtras {
            caller: req.from,
            effective_gas_price,
        };

        let mut trial = self.evm.clone();
        evm_transact(&mut trial, &tx, &block_env, extras).map_err(NodeError::Evm)
    }
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Node")
            .field("chain_id", &self.chain_id)
            .field("initial_supply", &self.initial_supply)
            .field("state_entries", &self.state.len())
            .field("tip", &self.tip)
            .finish_non_exhaustive()
    }
}
