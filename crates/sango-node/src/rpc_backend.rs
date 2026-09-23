//! Implémentation de `sango_rpc::RpcBackend` pour un nœud Sango.
//!
//! Le backend lit l'état via un [`NodeHandle`] partagé avec le `Driver`.
//! `send_transaction` pousse dans le mempool.

use sango_primitives::{Amount, ChainId32, Hash32, NativeAddress};
use sango_rpc::{RpcBackend, RpcError};
use sango_types::{Block, NativeAccount, Transaction, ValidatorInfo};

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
        // (1) Contexte : base fee courante + nonce du sender.
        let (base_fee, sender_nonce) = self.handle.with_node(|n| {
            let bf = n.expected_base_fee().unwrap_or(INITIAL_BASE_FEE);
            let sn = n.state().nonce_of(&tx.sender);
            (bf, sn)
        });

        // (2) Admission au mempool.
        self.handle.with_mempool(|pool| {
            pool.add(tx.clone(), base_fee, sender_nonce)
                .map_err(|e| RpcError::TransactionRejected(e.to_string()))
        })
    }
}

impl std::fmt::Debug for NodeBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeBackend").finish_non_exhaustive()
    }
}

// Marqueur pour éviter les imports inutilisés en cas de refactor.
#[allow(dead_code)]
fn _marker(_: Hash32) {}
