//! `sango-tx` — cycle de vie transactionnel Sango V1.
//!
//! ## Responsabilité
//!
//! Ce crate est **stateless** : il traite la transaction depuis ses bytes
//! jusqu'à sa validation, sans jamais toucher à l'état.
//!
//! ```text
//! bytes
//!   ↓
//! decode
//!   ↓
//! Transaction
//!   ↓
//! validate (structure, chain_id, signature, nonce, fee, balance)
//!   ↓
//! ValidatedTransaction
//! ```
//!
//! L'**application** d'une transaction validée (mutation d'état, fee
//! accounting, receipts) est la responsabilité du crate [`sango_exec`],
//! qui dépend à la fois de `sango-tx` et de `sango-state`.
//!
//! ## Pipeline (Freeze, section 2.8)
//!
//! ```text
//! decode → structure → chain_id → signature → nonce → balance → gas/fee
//! ```
//!
//! Chaque étape est exposée comme fonction indépendante.
//!
//! ## Bootstrap de clé publique
//!
//! Un compte est typiquement **crédité d'abord** par un transfert entrant :
//! il existe alors sous forme « fantôme » (`public_key == None`). Pour
//! pouvoir dépenser, il doit **activer** sa clé publique en la déclarant
//! dans sa première transaction (`tx.public_key = Some(pk)`).
//!
//! Voir [`validate_signature`] pour les règles exactes.
//!
//! ## Découplage
//!
//! `sango-tx` **ne dépend pas** de `sango-state`. La validation reçoit un
//! [`SenderInfo`] fourni par l'appelant.
//!
//! ## Frais
//!
//! ```text
//! effective_gas_price = min(max_fee, base_fee + priority_fee)
//! total_fee           = gas_used * effective_gas_price
//! validator_share     = total_fee * 9000 / 10000
//! burn_share          = total_fee - validator_share
//! ```
//!
//! Tous les calculs sont overflow-safe.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod fee;
mod validate;

pub use error::TxValidationError;
pub use fee::{effective_gas_price, split_fee, total_fee};
pub use validate::{
    validate_balance, validate_chain_id, validate_fee, validate_nonce, validate_signature,
    validate_structure, validate_transaction, SenderInfo, ValidatedTransaction, ValidationContext,
};
