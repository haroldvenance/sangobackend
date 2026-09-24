//! `sango-mpt` — Modified Merkle Patricia Trie **Ethereum-compatible**.
//!
//! Ce crate implémente les primitives de commitment Ethereum utilisées
//! par les roots qui **doivent** être Ethereum-compatibles (Freeze) :
//!
//! - `transaction_root` (bloc) — MPT de `RLP(index) → canonical_tx_bytes` ;
//! - `receipt_root` (bloc, à venir) — MPT de `RLP(index) → receipt_bytes` ;
//! - `evm_state_root` (à venir) — MPT des comptes EVM.
//!
//! ## Périmètre normatif
//!
//! Ce crate **ne touche pas** au SMT natif Sango (`sango-state`). Les deux
//! structures de commitment coexistent :
//!
//! ```text
//! native_state_root     ──► Sango SMT       (dans sango-state)
//! transaction_root      ──► Ethereum MPT   (ici)
//! receipt_root          ──► Ethereum MPT   (ici)
//! evm_state_root        ──► Ethereum MPT   (ici)
//! ```
//!
//! `state_root` et `block_hash` restent **Sango-specific** : ils combinent
//! ou hachent ces roots selon les formules du Freeze.
//!
//! ## Primitives Ethereum
//!
//! - **RLP** (crate `rlp`, Parity) — encode canonical des nœuds et clés.
//! - **Hex-prefix** — chemin nibble avec flag leaf/extension.
//! - **Keccak-256** — hash des nœuds et feuilles.
//! - **Règle des 32 bytes** — un nœud < 32 bytes est inliné dans son
//!   parent, sinon référencé par `Keccak256(encodage)`.
//!
//! ## Critère de sortie
//!
//! Pour chaque entrée, les propriétés suivantes sont testées :
//!
//! ```text
//! entries  →  root  →  proof(key)  →  verify(proof, key, root)
//! ```
//!
//! avec :
//!
//! - `EMPTY_ROOT` testé contre `Keccak256(RLP(""))` ;
//! - indépendance à l'ordre d'insertion des entrées ;
//! - preuve de présence ET d'absence ;
//! - sensibilité à toute mutation (racine, valeur, chemin).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod mpt;
mod nibbles;
mod node;

pub use error::MptError;
pub use mpt::{empty_root, mpt_proof, mpt_root, transaction_root, verify_proof};
pub use nibbles::{bytes_to_nibbles, from_hex_prefix, hex_prefix, nibbles_to_bytes};
pub use node::Node;
