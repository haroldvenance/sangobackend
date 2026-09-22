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
//! - métadonnées de chaîne.
//!
//! ## Règle normative (Freeze, section 55)
//!
//! **Le stockage physique ne définit jamais le consensus.**
//!
//! La structure RocksDB (colonnes, encodage clé/valeur, ordre des écritures)
//! est un détail d'implémentation. Le `native_state_root` est calculé par le
//! SMT de `sango-state` à partir des entrées persistées ; il ne dépend ni de
//! RocksDB ni de l'ordre d'insertion.
//!
//! ## Colonnes logiques
//!
//! ```text
//! blocks | block_headers | transactions | receipts
//! state_native | validators | staking | evidence
//! consensus | metadata
//! ```
//!
//! Chaque colonne correspond à une *column family* RocksDB.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod batch;
mod column;
mod db;
mod error;

pub use batch::Batch;
pub use column::Column;
pub use db::Storage;
pub use error::StorageError;
