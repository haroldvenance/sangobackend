//! `sango-wallet` — wallet CLI et bibliothèque pour Sango V1.
//!
//! ## Usage CLI
//!
//! ```text
//! sango-wallet [--rpc URL] [--keyfile PATH] <commande> [args...]
//! ```
//!
//! ## Commandes natives
//!
//! - `new` — génère un keyfile
//! - `address`, `pubkey`
//! - `balance [ADDR]`, `nonce [ADDR]`, `info`
//! - `send --to ADDR --amount SANGO`
//! - `stake`, `unstake`, `delegate`, `undelegate`, `claim`
//! - `register-validator`, `update-commission`, `unjail`
//!
//! ## Commandes EVM
//!
//! - `evm-new` — attache une clé secp256k1 au keyfile
//! - `evm-address` — adresse EVM locale
//! - `evm-balance [ADDR]`, `evm-nonce [ADDR]`
//! - `evm-call --to ADDR [--data HEX] [--value N]` — `eth_call`
//! - `evm-sign --to ADDR --value N [...]` — produit une tx EVM signée
//!   (hex), à broadcaster via `eth_sendRawTransaction` (à venir, 4c.3)
//!
//! ## Sécurité
//!
//! Le keyfile est stocké en JSON avec permissions `0600` sur Unix.
//! La graine Ed25519 (native) et le secret secp256k1 (EVM) sont deux
//! clés **indépendantes** dans le même fichier.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod cli;
pub mod commands;
mod error;
pub mod evm;
pub mod keystore;
pub mod rpc_client;

pub use error::WalletError;
pub use keystore::KeyFile;
pub use rpc_client::RpcClient;
