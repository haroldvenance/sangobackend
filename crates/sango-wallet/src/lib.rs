//! `sango-wallet` — wallet CLI et bibliothèque pour Sango V1.
//!
//! ## Usage CLI
//!
//! ```text
//! sango-wallet [--rpc URL] [--keyfile PATH] <commande> [args...]
//! ```
//!
//! Commandes :
//!
//! - `new` — génère un nouveau keyfile
//! - `address` — affiche l'adresse locale
//! - `balance [ADDR]` — affiche le solde
//! - `nonce [ADDR]` — affiche le nonce
//! - `info` — informations sur la chaîne
//! - `send --to ADDR --amount SANGO`
//! - `stake --amount SANGO` (top-up self-stake)
//! - `unstake --amount SANGO`
//! - `delegate --validator ADDR --amount SANGO`
//! - `undelegate --validator ADDR --amount SANGO`
//! - `claim --validator ADDR`
//! - `register-validator --commission-bps N --amount SANGO`
//! - `update-commission --new-bps N`
//! - `unjail`
//!
//! ## Sécurité
//!
//! Le keyfile est stocké en JSON avec permissions `0600` sur Unix. La
//! graine Ed25519 n'est **jamais** transmise au réseau : seul le wallet
//! l'utilise pour signer localement.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod cli;
pub mod commands;
mod error;
pub mod keystore;
pub mod rpc_client;

pub use error::WalletError;
pub use keystore::KeyFile;
pub use rpc_client::RpcClient;
