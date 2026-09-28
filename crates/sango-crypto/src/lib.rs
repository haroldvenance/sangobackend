//! `sango-crypto` — primitives cryptographiques natives de Sango V1.
//!
//! ## Choix normatifs (Freeze)
//!
//! - Hash : **Keccak-256** (`Keccak256`, **pas** `Sha3_256`).
//! - Signatures natives : **Ed25519** (comptes + validateurs).
//! - Signatures EVM : secp256k1 (ajoutées dans un module dédié).
//! - Domain separation : préfixe ASCII avant tout hash critique.
//! - Adresses natives : `Keccak256("SANGO/ADDRESS/V1" || pk)[0..20]`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod address;
pub mod bech32m;
pub mod domain;
pub mod ed25519;
pub mod hash;
pub mod hd;
pub mod mnemonic;

pub use address::{derive_native_address, evm_checksum_hex};
pub use bech32m::{
    decode_native_address, encode_native_address, try_decode_any_network, Bech32mError, Network,
};
pub use ed25519::{sign_native, verify_native, CryptoError, NativeKeypair};
pub use hash::{hash_domain, hash_domain_parts, keccak256};
pub use hd::{ChildIndex, DerivationPath, HdError, XPrvEd25519, XPrvSecp256k1};
pub use mnemonic::{Mnemonic, MnemonicError, MnemonicLength};
