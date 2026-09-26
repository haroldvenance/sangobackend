//! Implémentation de `sango_rpc::RpcBackend` pour un nœud Sango.
//!
//! Le backend lit l'état via un [`NodeHandle`] partagé avec le `Driver`.
//! `send_transaction` pousse dans le mempool ; `eth_call` exécute une
//! transaction EVM read-only sur un clone de l'`EvmState`.

use sango_primitives::{Amount, ChainId32, EvmAddress, Hash32, NativeAddress, U256};
use sango_rpc::{EthCallRequest, EthCallResult, RpcBackend, RpcError};
use sango_types::{Block, EvmTx, NativeAccount, Transaction, ValidatorInfo};

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

    fn send_transaction(&self, tx: &Transaction) -> Result<Hash32, RpcError> {
        let (base_fee, sender_nonce) = self.handle.with_node(|n| {
            let bf = n.expected_base_fee().unwrap_or(INITIAL_BASE_FEE);
            let sn = n.state().nonce_of(&tx.sender);
            (bf, sn)
        });

        self.handle.with_mempool(|pool| {
            pool.add(tx.clone(), base_fee, sender_nonce)
                .map_err(|e| RpcError::TransactionRejected(e.to_string()))
        })
    }

    // --- EVM ---------------------------------------------------------------

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
        let sender = sango_evm::recover_sender(&tx)
            .map_err(|_| RpcError::InvalidParams("invalid evm signature".into()))?;

        // (3) base_fee + nonce EVM courants.
        let (base_fee_u256, nonce) = self.handle.with_node(|n| {
            let bf = U256::from(n.expected_base_fee().unwrap_or(INITIAL_BASE_FEE));
            (bf, n.evm_get_nonce(&sender))
        });

        // (4) Push dans l'EvmMempool.
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
