//! `sango-tx` — validation de transactions natives Sango V1.
//!
//! ## Pipeline (Freeze, section 2.8)
//!
//! ```text
//! decode → structure → chain_id → signature → nonce → balance → gas/fee
//! ```
//!
//! ## Bootstrap de clé publique
//!
//! **RÉSOLU (A1).** Un compte natif est typiquement **crédité d'abord**
//! par un transfert entrant : il existe alors sous forme « fantôme »
//! (porteur d'un solde mais sans clé publique enregistrée). Pour pouvoir
//! dépenser, il doit **déclarer sa clé publique** dans sa première
//! transaction en renseignant `tx.public_key = Some(pk)`.
//!
//! Règles :
//!
//! - `tx.public_key = None` : la signature est vérifiée contre la clé
//!   publique du compte, qui doit déjà être enregistrée.
//! - `tx.public_key = Some(pk)` : `derive_native_address(pk) == tx.sender`
//!   requis. Si le compte a déjà une clé enregistrée, elle doit être
//!   **identique** (rotation interdite en V1).
//! - `PublicKey::ZERO` est rejeté structurellement.
//!
//! Le champ `public_key` est inclus dans les bytes signés et le hash de
//! transaction, ce qui empêche un attaquant de l'ajouter ou de le retirer
//! après signature.
//!
//! Le résultat de validation expose [`ValidatedTransaction::bootstrap_public_key`] :
//! s'il vaut `Some(pk)`, la couche d'état **doit** enregistrer `pk` comme
//! clé publique du compte lors de l'application.
//!
//! ## Découplage
//!
//! Ce crate **ne dépend pas** de `sango-state`. Les informations sur le
//! compte émetteur ([`SenderInfo`]) lui sont fournies par l'appelant.
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
