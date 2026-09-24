//! `sango-rpc` — serveur JSON-RPC 2.0 minimal pour Sango V1.
//!
//! ## Architecture
//!
//! ```text
//! Client HTTP ─► RpcServer ─► dispatch ─► RpcBackend (trait)
//!                                              ▲
//!                                              │
//!                                        implémenté par
//!                                        sango-node::NodeBackend
//! ```
//!
//! ## Méthodes supportées
//!
//! ### Sango natif
//!
//! | Méthode | Paramètres | Retour |
//! |---|---|---|
//! | `sango_chainId` | — | hex 32 bytes |
//! | `sango_blockNumber` | — | `u64` ou `null` |
//! | `sango_getBlock` | `[height]` | objet ou `null` |
//! | `sango_getAccount` | `[address]` | objet ou `null` |
//! | `sango_getBalance` | `[address]` | string décimale |
//! | `sango_getValidators` | — | tableau |
//! | `sango_sendTransaction` | `[hex_bytes]` | hash hex |
//! | `sango_chainInfo` | — | objet |
//!
//! ### Ethereum-compatible
//!
//! | Méthode | Paramètres | Retour |
//! |---|---|---|
//! | `eth_chainId` | — | hex |
//! | `eth_blockNumber` | — | hex |
//! | `eth_gasPrice` | — | hex |
//! | `eth_getBalance` | `[address, tag?]` | hex |
//! | `eth_getTransactionCount` | `[address, tag?]` | hex |
//! | `eth_getCode` | `[address, tag?]` | hex |
//! | `eth_getStorageAt` | `[address, slot, tag?]` | 0x + 64 hex |
//! | `eth_call` | `[{...}, tag?]` | hex |
//! | `eth_estimateGas` | `[{...}]` | hex |
//!
//! Le paramètre `tag` (block tag) est **ignoré en V1** : on interroge
//! toujours le tip courant.
//!
//! ## HTTP
//!
//! - `POST /rpc`
//! - `Content-Type: application/json`
//! - `Content-Length` obligatoire
//! - corps max 1 MiB
//! - pas de keep-alive

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod backend;
mod dispatch;
pub mod error;
mod http;
pub mod json;
mod server;

pub use backend::{EthCallRequest, EthCallResult, RpcBackend};
pub use error::RpcError;
pub use json::{ErrorObject, Request, Response};
pub use server::{RpcServer, ShutdownHandle};
