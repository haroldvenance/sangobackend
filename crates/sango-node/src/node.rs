//! Nœud Sango : orchestration validation → application → persistance.

use std::path::Path;

use sango_codec::{Decode, Encode};
use sango_exec::{apply_block as exec_apply_block, BlockExecutionResult, ExecutionContext};
use sango_primitives::{Amount, ChainId32, Hash32, NativeAddress};
use sango_state::{MetadataKey, NativeState};
use sango_storage::{metadata_key, Batch, Column, Storage};
use sango_tx::{validate_transaction, SenderInfo, ValidationContext};
use sango_types::{Block, BlockHeader, ChainTip};

use crate::base_fee::{next_base_fee, INITIAL_BASE_FEE};
use crate::diff::diff_state;
use crate::error::NodeError;

/// Nœud Sango.
pub struct Node {
    storage: Storage,
    state: NativeState,
    chain_id: ChainId32,
    initial_supply: Amount,
    tip: Option<ChainTip>,
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

        Ok(Self {
            storage,
            state,
            chain_id,
            initial_supply,
            tip,
        })
    }

    /// Vue en lecture sur l'état.
    #[must_use]
    pub fn state(&self) -> &NativeState {
        &self.state
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

    /// Construit un [`SenderInfo`] à partir de l'état courant.
    fn sender_info(&self, address: NativeAddress) -> SenderInfo {
        match self.state.get_account(&address) {
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

    /// Applique un bloc de bout en bout.
    ///
    /// ## Vérifications
    ///
    /// 1. `chain_id` du header correspond au nœud.
    /// 2. `previous_block_hash` correspond au tip (ou `ZERO` si vierge).
    /// 3. `height` vaut `tip.height + 1` (ou `0`/`1` si vierge).
    /// 4. `base_fee` correspond au calcul EIP-1559.
    /// 5. Chaque transaction est validée.
    pub fn apply_block(&mut self, block: &Block) -> Result<BlockExecutionResult, NodeError> {
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

        // (4) Validation par transaction.
        let mut validated = Vec::with_capacity(block.transactions.len());
        for (index, tx) in block.transactions.iter().enumerate() {
            let sender = self.sender_info(tx.sender);
            let vctx = ValidationContext {
                expected_chain_id: self.chain_id,
                base_fee: block.header.base_fee,
                sender: &sender,
            };
            let v = validate_transaction(tx, &vctx)
                .map_err(|e| NodeError::Validation { index, source: e })?;
            validated.push(v);
        }

        // (5) Snapshot + application.
        let state_before = self.state.clone();
        let ctx = ExecutionContext {
            chain_id: self.chain_id,
            base_fee: block.header.base_fee,
            fee_recipient: block.header.proposer_address,
            initial_supply: self.initial_supply,
            current_time: block.header.timestamp,
        };
        let result = exec_apply_block(&mut self.state, block, &validated, &ctx)?;

        // (6) Diff.
        let diff = diff_state(&state_before, &self.state);

        // (7) Batch.
        let block_hash = block.hash();
        let mut batch = Batch::new();
        batch.put(Column::Blocks, block_hash.as_bytes(), block.encode_to_vec());
        batch.put(
            Column::BlockHeaders,
            block_hash.as_bytes(),
            block.header.encode_to_vec(),
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

        // Tip.
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
            return Err(NodeError::Storage(e));
        }

        // (9) Mise à jour du tip en mémoire.
        self.tip = Some(new_tip);

        Ok(result)
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
