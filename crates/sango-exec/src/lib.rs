//! `sango-exec` — exécution des transactions natives Sango V1.
//!
//! ## Responsabilité
//!
//! Appliquer une transaction **déjà validée** à un état donné, et produire
//! le résultat d'exécution :
//!
//! ```text
//! ValidatedTransaction
//!         ↓
//!     sango-exec
//!         ↓
//!  ┌──────┴───────┐
//!  │              │
//!  ▼              ▼
//! state          result (receipt, fees, burned)
//! ```
//!
//! ## Position dans l'architecture
//!
//! ```text
//! sango-tx       (stateless, validation)
//!     ▲
//!     │
//! sango-exec     (application, mutations, fee accounting)
//!     │
//!     ▼
//! sango-state    (état canonique, SMT)
//! ```
//!
//! `sango-exec` dépend de `sango-tx` et `sango-state`. **Ni `sango-tx` ni
//! `sango-state` ne dépendent de `sango-exec`.**
//!
//! ## Atomicité
//!
//! L'application d'une transaction et l'application d'un bloc entier sont
//! **atomiques** : en cas d'échec à n'importe quelle étape, l'état est
//! restauré exactement comme avant l'appel.
//!
//! ## Extensions futures
//!
//! Ce crate accueillera également :
//!
//! - l'invocation EVM (`TX_CONTRACT_CALL`, `TX_CONTRACT_CREATE`) ;
//! - les mutations de staking (`sango-staking`) ;
//! - la génération de receipts (`sango-types::Receipt`) ;
//! - le calcul des roots (`transaction_root`, `receipt_root`).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod apply;
mod error;

pub use apply::{
    apply_block_transfers, apply_transfer, apply_transfer_with_gas, BlockApplyResult,
    NATIVE_TRANSFER_GAS,
};
pub use error::ApplyError;

pub use apply::AppliedTransaction;
