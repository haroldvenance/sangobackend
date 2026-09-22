//! `sango-exec` — exécution des transactions natives Sango V1.
//!
//! ## Responsabilité
//!
//! Appliquer une transaction **déjà validée** à un état donné, et produire
//! le résultat d'exécution.
//!
//! ```text
//! sango-tx       (stateless, validation)
//!     ▲
//!     │
//! sango-exec     (application, mutations, fee accounting, receipts)
//!     │
//!     ▼
//! sango-state    (état canonique, SMT)
//! ```
//!
//! ## Points d'entrée
//!
//! - [`apply_transfer`] / [`apply_transfer_with_gas`] : une transaction.
//! - [`apply_block_transfers`] : plusieurs transactions sans `BlockHeader`.
//! - [`apply_block`] : bloc complet avec receipts et offre courante.
//!
//! ## Compteurs globaux
//!
//! `apply_block` agrège les frais brûlés et le gas consommé et effectue
//! **un seul** appel à `add_burned` + `add_gas_used` par bloc. C'est plus
//! efficace que des écritures par transaction.
//!
//! ## Atomicité
//!
//! Tous les points d'entrée sont atomiques. En cas d'échec, l'état est
//! restauré (snapshot + rollback).
//!
//! ## Extensions futures
//!
//! Ce crate accueillera :
//!
//! - l'invocation EVM (`TX_CONTRACT_CALL`, `TX_CONTRACT_CREATE`) ;
//! - les mutations de staking (`sango-staking`) ;
//! - le `receipt_root` (MPT des receipts, à venir).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod apply;
mod error;

pub use apply::{
    apply_block, apply_block_transfers, apply_transfer, apply_transfer_with_gas,
    AppliedTransaction, BlockApplyResult, BlockExecutionResult, ExecutionContext,
    NATIVE_TRANSFER_GAS,
};
pub use error::ApplyError;
