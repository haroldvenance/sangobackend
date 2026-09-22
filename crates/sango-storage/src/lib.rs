//! `sango-storage` — persistance RocksDB du nœud Sango V1.
//!
//! ## Rôle
//!
//! Persister les données du protocole :
//!
//! - blocs et en-têtes ;
//! - transactions et receipts ;
//! - entrées d'état natif (SMT) ;
//! - état validateurs, staking, evidence, consensus ;
//! - métadonnées globales (`total_burned`, `total_gas_used`).
//!
//! ## Règle normative (Freeze, section 55)
//!
//! **Le stockage physique ne définit jamais le consensus.**
//!
//! La structure RocksDB est un détail d'implémentation. Le
//! `native_state_root` est calculé par le SMT de `sango-state` à partir
//! des entrées ; il ne dépend ni de RocksDB ni de l'ordre d'insertion.
//!
//! ## Colonnes logiques
//!
//! ```text
//! blocks | block_headers | transactions | receipts
//! state_native | validators | staking | evidence
//! consensus | metadata
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod batch;
mod column;
mod db;
mod error;
mod metadata;

pub use batch::Batch;
pub use column::Column;
pub use db::Storage;
pub use error::StorageError;
pub use metadata::metadata_key;
