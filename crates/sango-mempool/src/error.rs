//! Erreurs du mempool natif et EVM.

use sango_primitives::{Hash32, U256};
use thiserror::Error;

/// Erreurs du mempool natif.
///
/// ## Contrat
///
/// Le mempool reçoit des [`crate::Mempool::add`] uniquement des
/// transactions **pré-validées** par `sango_tx::validate_for_mempool`.
/// Les erreurs de validation (signature, chain_id, fee, nonce hors
/// fenêtre, balance) sont donc retournées **en amont** par
/// `sango_tx::TxValidationError`, pas par cette enum.
///
/// Seules les règles **locales au pool** apparaissent ici.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MempoolError {
    /// Transaction déjà connue (hash présent).
    #[error("duplicate transaction: {0:?}")]
    Duplicate(Hash32),

    /// Capacité du pool atteinte (globale ou par sender).
    #[error("mempool full")]
    Full,

    /// Collision de nonce sans bump de prix suffisant.
    #[error("replacement fee too low: needed {needed}, got {got}")]
    ReplacementFeeTooLow {
        /// Prix effectif minimal requis pour remplacer.
        needed: u128,
        /// Prix effectif offert par la nouvelle tx.
        got: u128,
    },

    /// Le `ValidatedTransaction` fourni ne correspond pas à la
    /// `Transaction` passée à `pool.add()`.
    ///
    /// **Défense en profondeur** : `validate_for_mempool` produit un
    /// couple `(tx, ValidatedTransaction)` cohérent. Ce variant signale
    /// un caller qui aurait fourni une tx modifiée après validation, ou
    /// un `ValidatedTransaction` construit à la main avec un mauvais
    /// `tx_hash` / `sender`.
    #[error("validated transaction does not match provided transaction")]
    ValidationMismatch,
}

/// Erreurs du mempool EVM.
///
/// Aligné sur `evm_pool.rs` : les prix EVM sont en `U256` (EIP-1559),
/// pas en `u128`. Le sender est **toujours** récupéré par
/// `recover_sender()` (signature secp256k1) — jamais fourni par
/// l'appelant. Le mempool EVM n'a donc **pas** besoin d'un
/// `ValidationMismatch` : `recover_sender` rejette toute signature
/// invalide avant toute insertion.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EvmMempoolError {
    /// Transaction EVM déjà connue (hash présent).
    #[error("duplicate evm transaction: {0:?}")]
    Duplicate(Hash32),

    /// Capacité du pool EVM atteinte (globale ou par sender).
    #[error("evm mempool full")]
    Full,

    /// Signature secp256k1 invalide (recovery échouée, `y_parity > 1`,
    /// point public malformé).
    #[error("invalid evm signature")]
    InvalidSignature,

    /// `max_fee_per_gas < base_fee`.
    #[error("evm max_fee ({max_fee}) below base_fee ({base_fee})")]
    MaxFeeBelowBaseFee {
        /// `max_fee_per_gas` de la tx EVM (U256).
        max_fee: U256,
        /// Base fee courante (U256).
        base_fee: U256,
    },

    /// Nonce EVM inférieur au nonce courant.
    #[error("evm nonce too low: expected {expected}, got {got}")]
    NonceTooLow {
        /// Nonce attendu (nonce courant du compte).
        expected: u64,
        /// Nonce fourni par la tx.
        got: u64,
    },

    /// Nonce EVM supérieur à la fenêtre acceptée.
    #[error("evm nonce too high: expected {expected}, got {got}")]
    NonceTooHigh {
        /// Nonce maximal accepté (`account.nonce + max_nonce_gap`).
        expected: u64,
        /// Nonce fourni par la tx.
        got: u64,
    },

    /// Collision de nonce EVM sans bump de priorité suffisant.
    #[error("evm replacement fee too low: needed {needed}, got {got}")]
    ReplacementFeeTooLow {
        /// Priorité effective minimale requise (U256).
        needed: U256,
        /// Priorité effective offerte par la nouvelle tx (U256).
        got: U256,
    },
}