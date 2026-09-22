//! `sango-tx` — validation de transactions natives Sango V1.
//!
//! ## Pipeline (Freeze, section 2.8)
//!
//! ```text
//! decode → structure → chain_id → signature → nonce → balance → gas/fee
//! ```
//!
//! Chaque étape est exposée comme fonction indépendante.
//!
//! ## Découplage
//!
//! Ce crate **ne dépend pas** de `sango-state` ni de `sango-storage`. Les
//! informations sur le compte émetteur ([`SenderInfo`]) lui sont fournies
//! par l'appelant. Cette séparation permet :
//!
//! - de tester la validation sans base de données ;
//! - de réutiliser le validateur dans plusieurs contextes (mempool, block
//!   building, RPC).
//!
//! ## Source de la clé publique — À SPÉCIFIER
//!
//! **Statut : OUVERT.** Le Freeze V1 ne définit pas encore comment un nœud
//! obtient la clé publique d'un compte natif. Options envisagées :
//!
//! - **A1** — la première transaction d'un compte fournit sa clé publique
//!   (champ optionnel dans `Transaction`) ; création implicite du compte si
//!   `derive(public_key) == tx.sender` et signature valide.
//! - **A2** — comptes précréés par Genesis ou opération protocolaire.
//! - **A3** — clé publique dans **toutes** les transactions.
//!
//! Recommandation : **A1**.
//!
//! En attendant la décision, `sango-tx` utilise [`SenderInfo`] et ne
//! présuppose ni la structure de `NativeAccount` ni le format final de
//! `Transaction`.
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
