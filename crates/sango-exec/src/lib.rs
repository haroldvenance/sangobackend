//! `sango-exec` — exécution des transactions natives Sango V1.
//!
//! ## Responsabilité
//!
//! Appliquer une transaction **déjà validée** à un état donné, et produire
//! le résultat d'exécution.
//!
//! ## Points d'entrée
//!
//! - [`apply_transfer`] / [`apply_transfer_with_gas`] : transfert natif seul.
//! - [`apply_block_transfers`] : plusieurs transactions (native + staking).
//! - [`apply_block`] : bloc complet avec receipts et offre courante.
//!
//! ## Extensions futures
//!
//! - Invocation EVM (`TX_CONTRACT_CALL`, `TX_CONTRACT_CREATE`).
//! - Distribution des récompenses PoS et slashing.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod apply;
mod error;
pub mod staking;

pub use apply::{
    apply_block, apply_block_transfers, apply_transfer, apply_transfer_with_gas,
    apply_tx_no_rollback, AppliedTransaction, BlockApplyResult, BlockExecutionResult,
    ExecutionContext, NATIVE_TRANSFER_GAS,
};
pub use error::ApplyError;
pub use staking::{apply_staking_no_rollback, gas_for};
