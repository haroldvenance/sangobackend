//! `sango-state` — état canonique natif de Sango V1.
//!
//! ## Structure normative FROZEN V1
//!
//! L'état natif est commité par un **Sparse Merkle Tree binaire de 256 niveaux**
//! utilisant **Keccak-256** :
//!
//! - **clé** : `K = namespace_u8 || identifier`, hashée en
//!   `key_hash = Keccak256("SANGO/STATE/KEY/V1" || K)` ;
//! - **feuille** :
//!   `Keccak256("SANGO/STATE/LEAF/V1" || key_hash || u32_be(value_len) || value)` ;
//! - **nœud interne** :
//!   `Keccak256("SANGO/STATE/NODE/V1" || left || right)` ;
//! - **feuille vide** :
//!   `EMPTY[0] = Keccak256("SANGO/STATE/EMPTY/LEAF/V1")` ;
//! - **remontée vide** : `EMPTY[i+1] = H(NODE_V1 || EMPTY[i] || EMPTY[i])` ;
//! - **racine vide** : `EMPTY[256]`.
//!
//! Le `state_root` global du `BlockHeader` reste :
//!
//! ```text
//! state_root = Keccak256(
//!     "SANGO/STATE/ROOT/V1" || native_state_root || evm_state_root
//! )
//! ```
//!
//! RocksDB (dans `sango-storage`) ne fait que persister les entrées ; il ne
//! définit jamais le consensus.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod namespace;
mod native;
mod root;
mod smt;

pub use error::StateError;
pub use namespace::Namespace;
pub use native::{state_key_hash, NativeState};
pub use root::global_state_root;
pub use smt::{empty_root, SparseMerkleTree, TREE_HEIGHT};
