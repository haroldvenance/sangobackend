//! Implémentation de `sango_rpc::RpcBackend` pour un nœud Sango.
//!
//! Le backend lit l'état via un [`NodeHandle`] partagé avec le `Driver`.
//! `send_transaction` valide **cryptographiquement** (via
//! `sango_tx::validate_for_mempool`) **avant** d'insérer dans le
//! mempool. `eth_call` exécute une transaction EVM read-only sur un
//! clone de l'`EvmState`.

use sango_primitives::{Amount, ChainId32, EvmAddress, Hash32, NativeAddress, U256};
use sango_rpc::{EthCallRequest, EthCallResult, RpcBackend, RpcError};
use sango_tx::{validate_for_mempool, SenderInfo, ValidationContext};
use sango_types::{
    Block, Delegation, EvmTx, NativeAccount, PendingUnbonding, Receipt, Transaction, Tx, TxOutcome,
    ValidatorInfo,
};

use crate::base_fee::INITIAL_BASE_FEE;
use crate::node_handle::NodeHandle;

/// Backend RPC branché sur un `NodeHandle`.
pub struct NodeBackend {
    handle: NodeHandle,
}

impl NodeBackend {
    /// Crée un backend à partir d'un handle.
    #[must_use]
    pub fn new(handle: NodeHandle) -> Self {
        Self { handle }
    }

    /// Handle partagé (utile pour brancher d'autres composants).
    #[must_use]
    pub fn handle(&self) -> &NodeHandle {
        &self.handle
    }
}

impl RpcBackend for NodeBackend {
    // --- Natif -------------------------------------------------------------

    fn chain_id(&self) -> ChainId32 {
        self.handle.with_node(|n| n.chain_id())
    }

    fn block_number(&self) -> Option<u64> {
        self.handle.with_node(|n| n.tip().map(|t| t.height.get()))
    }

    fn get_block_by_height(&self, height: u64) -> Option<Block> {
        self.handle
            .with_node(|n| n.get_block_by_height(height).ok().flatten())
    }

    fn get_account(&self, address: &NativeAddress) -> Option<NativeAccount> {
        self.handle.with_node(|n| n.state().get_account(address))
    }

    fn get_balance(&self, address: &NativeAddress) -> Amount {
        self.handle.with_node(|n| n.state().balance_of(address))
    }

    fn get_validators(&self) -> Vec<ValidatorInfo> {
        self.handle.with_node(|n| n.all_validators())
    }

    fn sango_base_fee(&self) -> u128 {
        self.handle
            .with_node(|n| n.expected_base_fee().unwrap_or(INITIAL_BASE_FEE))
    }

    fn get_validator_info(&self, address: &NativeAddress) -> Option<ValidatorInfo> {
        self.handle.with_node(|n| n.state().get_validator(address))
    }

    fn get_delegations_of(&self, delegator: &NativeAddress) -> Vec<Delegation> {
        self.handle.with_node(|n| n.get_delegations_of(delegator))
    }

    fn get_pending_unbondings_for(&self, delegator: &NativeAddress) -> Vec<PendingUnbonding> {
        self.handle
            .with_node(|n| n.get_pending_unbondings_for(delegator))
    }

    fn get_transaction_with_location(&self, hash: &Hash32) -> Option<(Tx, sango_rpc::TxLocation)> {
        self.handle
            .with_node(|n| n.get_transaction_with_location(hash).ok().flatten())
    }

    fn get_transactions_by_address(
        &self,
        address: &NativeAddress,
        limit: u32,
        offset: u32,
    ) -> (Vec<(Tx, sango_rpc::TxLocation)>, u64) {
        self.handle.with_node(|n| {
            n.get_transactions_by_address(address, limit, offset)
                .unwrap_or_default()
        })
    }

    fn get_tx_outcome(&self, hash: &Hash32) -> Option<TxOutcome> {
        self.handle
            .with_node(|n| n.get_tx_outcome(hash).ok().flatten())
    }

    /// Soumet une transaction native au mempool.
    ///
    /// ## Pipeline (P0 sécurité)
    ///
    /// 1. Lecture (snapshot) : `chain_id`, `base_fee`, `SenderInfo`, `max_gap`.
    /// 2. **Validation cryptographique complète** :
    ///    `sango_tx::validate_for_mempool` vérifie structure, chain_id,
    ///    signature Ed25519, nonce ∈ fenêtre, fee, balance.
    ///    Toute tx invalide (signature fausse, chain_id erroné, nonce
    ///    hors fenêtre, solde insuffisant) est **rejetée ici**, avant
    ///    d'atteindre le mempool.
    /// 3. Insertion mempool : `pool.add(tx, &validated)`. Le
    ///    `ValidatedTransaction` sert de preuve que l'étape 2 a réussi.
    ///
    /// Sans cette validation, un attaquant pourrait forger des `tx.sender`
    /// (signature = `Signature::ZERO`) et remplir le mempool en
    /// marquant `per_sender_count[victim] = max_per_sender` → toutes
    /// les tx réelles de `victim` seraient rejetées (`Full`).
    fn send_transaction(&self, tx: &Transaction) -> Result<Hash32, RpcError> {
        // (1) Snapshot état + config mempool.
        //     Locks relâchés avant la validation cryptographique (qui
        //     peut prendre ~100 µs avec Ed25519).
        let (chain_id, base_fee, sender_info) = self.handle.with_node(|n| {
            let bf = n.expected_base_fee().unwrap_or(INITIAL_BASE_FEE);
            let sender_info = match n.state().get_account(&tx.sender) {
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
                None => SenderInfo::ghost(tx.sender, 0, 0),
            };
            (n.chain_id(), bf, sender_info)
        });

        let max_gap = self
            .handle
            .with_mempool(|p| p.config().max_nonce_gap);

        // (2) Validation cryptographique (cœur de la protection P0).
        let ctx = ValidationContext {
            expected_chain_id: chain_id,
            base_fee,
            sender: &sender_info,
        };
        let validated = validate_for_mempool(tx, &ctx, max_gap).map_err(|e| {
            // Erreur de validation : on renvoie un message court au client.
            // Le message complet peut contenir un chain_id, une adresse —
            // c'est acceptable pour un RPC public (les mêmes données sont
            // visibles on-chain), mais on évite toute stack trace.
            RpcError::TransactionRejected(format!("{e}"))
        })?;

        // (3) Insertion mempool (protégée par le proof).
        self.handle.with_mempool(|pool| {
            pool.add(tx.clone(), &validated)
                .map_err(|e| RpcError::TransactionRejected(e.to_string()))
        })
    }

    // --- EVM ---------------------------------------------------------------

    fn eth_get_transaction_with_location(
        &self,
        hash: &Hash32,
    ) -> Option<(EvmTx, sango_rpc::TxLocation)> {
        self.handle
            .with_node(|n| n.eth_get_transaction_with_location(hash).ok().flatten())
    }

    fn eth_get_receipt_bundle(
        &self,
        hash: &Hash32,
    ) -> Option<(Receipt, sango_rpc::TxLocation, u64)> {
        self.handle
            .with_node(|n| n.eth_get_receipt_bundle(hash).ok().flatten())
    }

    fn eth_get_block_with_receipts_by_number(&self, height: u64) -> Option<(Block, Vec<Receipt>)> {
        self.handle.with_node(|n| {
            n.eth_get_block_with_receipts_by_number(height)
                .ok()
                .flatten()
        })
    }

    fn eth_get_block_with_receipts_by_hash(&self, hash: &Hash32) -> Option<(Block, Vec<Receipt>)> {
        self.handle
            .with_node(|n| n.eth_get_block_with_receipts_by_hash(hash).ok().flatten())
    }

    fn eth_chain_id(&self) -> u64 {
        self.handle.with_node(|n| n.evm_chain_id())
    }

    fn eth_gas_price(&self) -> U256 {
        self.handle.with_node(|n| {
            let base_fee = n.expected_base_fee().unwrap_or(INITIAL_BASE_FEE);
            U256::from(base_fee)
        })
    }

    fn eth_get_balance(&self, address: &EvmAddress) -> U256 {
        self.handle.with_node(|n| n.evm_get_balance(address))
    }

    fn eth_get_transaction_count(&self, address: &EvmAddress) -> u64 {
        self.handle.with_node(|n| n.evm_get_nonce(address))
    }

    fn eth_get_code(&self, address: &EvmAddress) -> Vec<u8> {
        self.handle.with_node(|n| n.evm_get_code(address))
    }

    fn eth_get_storage_at(&self, address: &EvmAddress, slot: U256) -> U256 {
        self.handle.with_node(|n| n.evm_get_storage(address, slot))
    }

    fn eth_call(&self, req: &EthCallRequest) -> Result<EthCallResult, RpcError> {
        let outcome = self.handle.with_node(|n| {
            n.evm_call_readonly(req)
                .map_err(|e| RpcError::Internal(format!("evm_call: {e}")))
        })?;
        Ok(EthCallResult {
            success: outcome.success,
            output: outcome.output,
            gas_used: outcome.gas_used,
        })
    }

    fn eth_estimate_gas(&self, req: &EthCallRequest) -> Result<u64, RpcError> {
        let outcome = self.handle.with_node(|n| {
            n.evm_call_readonly(req)
                .map_err(|e| RpcError::Internal(format!("evm_estimate: {e}")))
        })?;
        Ok(outcome.gas_used)
    }

    fn eth_send_raw_transaction(&self, raw: &[u8]) -> Result<Hash32, RpcError> {
        // (1) Décoder le typed-transaction Ethereum.
        let tx = EvmTx::decode_ethereum_typed(raw)
            .map_err(|e| RpcError::InvalidParams(format!("decode evm tx: {e}")))?;

        // (2) Récupérer le sender cryptographiquement.
        //     C'est l'équivalent EVM de validate_signature : la signature
        //     ECDSA secp256k1 est vérifiée et l'adresse dérivée.
        let sender = sango_evm::recover_sender(&tx)
            .map_err(|_| RpcError::InvalidParams("invalid evm signature".into()))?;

        // (3) base_fee + nonce EVM courants.
        let (base_fee_u256, nonce) = self.handle.with_node(|n| {
            let bf = U256::from(n.expected_base_fee().unwrap_or(INITIAL_BASE_FEE));
            (bf, n.evm_get_nonce(&sender))
        });

        // (4) Push dans l'EvmMempool.
        //
        // ⚠️ TODO(sécurité EVM) : l'EvmMempool ne reçoit pas encore de
        // `ValidatedTransaction` équivalent. Recommandation : créer
        // `sango_evm::validate_for_mempool(evm_tx, &evm_sender_info, &ctx)`
        // et faire le même pattern que pour le natif (preuve → pool).
        // Sans cela, le pool EVM reste exposé au même grief que le pool
        // natif l'était avant ce patch.
        self.handle.with_evm_mempool(|pool| {
            pool.add(tx, base_fee_u256, nonce)
                .map_err(|e| RpcError::TransactionRejected(e.to_string()))
        })
    }

    fn eth_get_logs(
        &self,
        filter: &sango_rpc::EthLogFilter,
    ) -> Result<Vec<sango_rpc::EthLog>, RpcError> {
        self.handle.with_node(|n| {
            n.eth_get_logs(filter)
                .map_err(|e| RpcError::Internal(format!("eth_getLogs: {e}")))
        })
    }

    fn eth_get_proof(
        &self,
        address: &EvmAddress,
        storage_keys: &[U256],
        block: Option<u64>,
    ) -> Result<sango_rpc::EthProof, RpcError> {
        self.handle.with_node(|n| {
            n.eth_get_proof(address, storage_keys, block)
                .map_err(|e| RpcError::Internal(format!("eth_getProof: {e}")))
        })
    }
}

impl std::fmt::Debug for NodeBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeBackend").finish_non_exhaustive()
    }
}