//! Erreurs du nœud.

use sango_exec::ApplyError;
use sango_primitives::Hash32;
use sango_storage::StorageError;
use sango_tx::TxValidationError;
use thiserror::Error;

/// Erreur produite par [`crate::Node`].
#[derive(Debug, Error)]
pub enum NodeError {
    /// Erreur de persistance.
    #[error("storage: {0}")]
    Storage(#[from] StorageError),

    /// Erreur de validation d'une transaction.
    #[error("validation failed for tx {index}: {source}")]
    Validation {
        /// Index de la transaction dans le bloc.
        index: usize,
        /// Erreur sous-jacente.
        #[source]
        source: TxValidationError,
    },

    /// Erreur de validation d'une transaction EVM.
    #[error("evm validation failed for tx {index}: {reason}")]
    EvmValidation {
        /// Index de la transaction dans le bloc.
        index: usize,
        /// Raison courte.
        reason: String,
    },

    /// Erreur d'application d'un bloc.
    #[error("apply: {0}")]
    Apply(#[from] ApplyError),

    /// Une entrée d'état restaurée depuis la base n'a pas la taille
    /// attendue pour un `key_hash`.
    #[error("corrupted state entry: expected 32-byte key, got {got}")]
    CorruptedStateKey {
        /// Taille effectivement lue.
        got: usize,
    },

    /// Le header du bloc parent n'a pas été trouvé dans RocksDB.
    #[error("parent header not found: {hash}")]
    ParentHeaderNotFound {
        /// Hash du header parent.
        hash: Hash32,
    },

    /// Le `chain_id` du bloc ne correspond pas à celui du nœud.
    #[error("block chain_id mismatch")]
    ChainIdMismatch,

    /// Le `previous_block_hash` du bloc ne correspond pas au tip courant.
    #[error("previous_block_hash mismatch: expected {expected}, got {got}")]
    ParentHashMismatch {
        /// Hash attendu (tip courant ou `ZERO` pour un nœud vierge).
        expected: Hash32,
        /// Hash effectivement reçu.
        got: Hash32,
    },

    /// La hauteur du bloc ne suit pas celle du tip courant.
    #[error("height mismatch: expected {expected}, got {got}")]
    HeightMismatch {
        /// Hauteur attendue.
        expected: u64,
        /// Hauteur reçue.
        got: u64,
    },

    /// Le `base_fee` du bloc ne correspond pas à celui calculé selon
    /// EIP-1559.
    #[error("base_fee mismatch: expected {expected}, got {got}")]
    BaseFeeMismatch {
        /// Base fee attendue.
        expected: u128,
        /// Base fee reçue.
        got: u128,
    },

    /// Le `transaction_root` du header ne correspond pas au contenu réel
    /// du bloc (MPT Ethereum recalculé localement).
    #[error("transaction_root mismatch: expected {expected}, got {got}")]
    TransactionRootMismatch {
        /// Racine recalculée depuis les transactions du bloc.
        expected: Hash32,
        /// Racine déclarée dans le header.
        got: Hash32,
    },

    /// Le `receipt_root` du header ne correspond pas aux receipts
    /// d'exécution recalculés localement (MPT Ethereum).
    #[error("receipt_root mismatch: expected {expected}, got {got}")]
    ReceiptRootMismatch {
        /// Racine recalculée depuis les receipts d'exécution.
        expected: Hash32,
        /// Racine déclarée dans le header.
        got: Hash32,
    },

    /// Le `state_root` du header ne correspond pas au recalcul local
    /// (`Keccak256("SANGO/STATE/ROOT/V1" || native || evm)`).
    #[error("state_root mismatch: expected {expected}, got {got}")]
    StateRootMismatch {
        /// Racine recalculée depuis l'état natif + l'état EVM.
        expected: Hash32,
        /// Racine déclarée dans le header.
        got: Hash32,
    },

    /// Le nœud a déjà été initialisé (tip présent).
    #[error("node already initialized")]
    AlreadyInitialized,

    /// Erreur de configuration / genesis.
    #[error("config: {0}")]
    Config(#[from] crate::config::ConfigError),

    /// Erreur d'exécution EVM (revm bridge).
    #[error("evm: {0}")]
    Evm(#[from] sango_evm::EvmError),

    /// Le bloc a déjà été appliqué (le tip pointe dessus).
    #[error("block already applied: {hash}")]
    AlreadyApplied {
        /// Hash du bloc déjà appliqué.
        hash: sango_primitives::Hash32,
    },
}
