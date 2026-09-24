//! `sango-evm` — stockage EVM Ethereum-compatible + bridge revm.
//!
//! ## Périmètre 4c.1
//!
//! - Encodage/décodage RLP **Ethereum exact** d'un [`EvmAccount`] ;
//! - [storage trie](StorageTrie) par compte ;
//! - **stockage de code** par `code_hash` ;
//! - [`EvmState`] complet (accounts + storage + code) ;
//! - [bridge revm](revm_bridge) : `Database` + `DatabaseCommit` isolés.
//!
//! ## Non périmètre (4c.2+)
//!
//! - Câblage revm dans `apply_block` ;
//! - Dérivation normative de `prevrandao` (proposée, à figer) ;
//! - Fee model Sango appliqué à `TxEnv`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod account;
mod error;
pub mod revm_bridge;
mod state;
mod storage;

pub use account::{decode_account, empty_code_hash, encode_account};
pub use error::EvmError;
pub use revm_bridge::{
    evm_transact, from_b256, from_revm_address, to_b256, to_revm_address, EvmBlockEnv, EvmDb,
    EvmOutcome, TxEnvExtras,
};
pub use state::{is_eoa_empty, EvmState};
pub use storage::{decode_storage_value, encode_storage_value, slot_mpt_key, StorageTrie};
