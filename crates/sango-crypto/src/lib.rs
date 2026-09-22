//! `sango-crypto` — primitives cryptographiques natives de Sango V1.
//!
//! ## Choix normatifs (Freeze)
//!
//! - Hash : **Keccak-256** (`Keccak256`, **pas** `Sha3_256`).
//! - Signatures natives : **Ed25519** (comptes + validateurs).
//! - Signatures EVM : secp256k1 (seront ajoutées dans un module dédié).
//! - Domain separation : préfixe ASCII avant tout hash critique.
//!
//! ## Ce que ce crate n’est pas
//!
//! - Il n’implémente aucune primitive cryptographique nouvelle.
//! - Il ne définit **pas** l’encodage consensus (voir `sango-codec`).
//! - Il ne contient **aucune** logique métier (validateurs, slashing, etc.).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod domain;
pub mod ed25519;
pub mod hash;

pub use ed25519::{sign_native, verify_native, CryptoError, NativeKeypair};
pub use hash::{hash_domain, hash_domain_parts, keccak256};
