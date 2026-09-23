//! `sango-exec` — exécution des transactions natives Sango V1.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod apply;
mod error;
pub mod slashing;
pub mod staking;

pub use apply::{
    apply_block, apply_block_transfers, apply_transfer, apply_transfer_with_gas,
    apply_tx_no_rollback, AppliedTransaction, BlockApplyResult, BlockExecutionResult,
    ExecutionContext, NATIVE_TRANSFER_GAS,
};
pub use error::ApplyError;
pub use slashing::{apply_evidence, EvidenceApplied, DOUBLE_SIGN_JAIL_SECS};
pub use staking::{apply_staking_no_rollback, gas_for};
