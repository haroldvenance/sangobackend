//! Erreurs de la couche de persistance.

use thiserror::Error;

/// Erreur produite par [`crate::Storage`].
#[derive(Debug, Error)]
pub enum StorageError {
    /// Erreur RocksDB sous-jacente.
    #[error("rocksdb: {0}")]
    RocksDb(String),

    /// Colonne logique inconnue (ne devrait pas arriver en pratique).
    #[error("unknown column: {name}")]
    UnknownColumn {
        /// Nom de la colonne.
        name: String,
    },

    /// Erreur d'encodage / décodage canonique.
    #[error("codec: {0}")]
    Codec(#[from] sango_codec::CodecError),
}

impl From<rocksdb::Error> for StorageError {
    fn from(e: rocksdb::Error) -> Self {
        Self::RocksDb(e.to_string())
    }
}
