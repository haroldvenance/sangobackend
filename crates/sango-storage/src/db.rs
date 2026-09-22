//! Backend RocksDB.

use std::path::Path;

use rocksdb::{ColumnFamilyDescriptor, Options, WriteBatch, DB};

use crate::batch::{Batch, Operation};
use crate::column::Column;
use crate::error::StorageError;

/// Stockage persistant RocksDB.
///
/// Le stockage physique **ne définit jamais le consensus**. Le
/// `native_state_root` est calculé par le SMT de `sango-state`, à partir des
/// entrées persistées ici.
pub struct Storage {
    db: DB,
}

impl Storage {
    /// Ouvre (ou crée) un stockage RocksDB à l'emplacement `path`.
    ///
    /// Crée les column families manquantes.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cf_descriptors: Vec<ColumnFamilyDescriptor> = Column::ALL
            .iter()
            .map(|c| ColumnFamilyDescriptor::new(c.name(), Options::default()))
            .collect();

        let db = DB::open_cf_descriptors(&opts, path, cf_descriptors)?;
        Ok(Self { db })
    }

    /// Récupère le handle de column family pour une colonne.
    fn cf(&self, column: Column) -> Result<&rocksdb::ColumnFamily, StorageError> {
        self.db
            .cf_handle(column.name())
            .ok_or_else(|| StorageError::UnknownColumn {
                name: column.name().to_string(),
            })
    }

    /// Écrit une paire clé/valeur dans une colonne.
    pub fn put(&self, column: Column, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        let cf = self.cf(column)?;
        self.db.put_cf(cf, key, value)?;
        Ok(())
    }

    /// Lit une valeur.
    pub fn get(&self, column: Column, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let cf = self.cf(column)?;
        Ok(self.db.get_cf(cf, key)?)
    }

    /// Supprime une clé.
    pub fn delete(&self, column: Column, key: &[u8]) -> Result<(), StorageError> {
        let cf = self.cf(column)?;
        self.db.delete_cf(cf, key)?;
        Ok(())
    }

    /// Vrai si la clé existe.
    pub fn contains(&self, column: Column, key: &[u8]) -> Result<bool, StorageError> {
        Ok(self.get(column, key)?.is_some())
    }

    /// Applique un batch d'écritures atomiquement.
    ///
    /// Toutes les opérations du batch sont commitées ensemble, ou aucune.
    pub fn write_batch(&self, batch: Batch) -> Result<(), StorageError> {
        let mut wb = WriteBatch::default();

        for op in batch.into_ops() {
            match op {
                Operation::Put { column, key, value } => {
                    let cf = self.cf(column)?;
                    wb.put_cf(cf, key, value);
                }
                Operation::Delete { column, key } => {
                    let cf = self.cf(column)?;
                    wb.delete_cf(cf, key);
                }
            }
        }

        self.db.write(wb)?;
        Ok(())
    }

    /// Force le flush sur disque. Utile avant un arrêt propre.
    pub fn flush(&self) -> Result<(), StorageError> {
        self.db.flush()?;
        Ok(())
    }
}

impl std::fmt::Debug for Storage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Storage").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batch::Batch;

    fn temp_storage() -> (tempfile::TempDir, Storage) {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::open(dir.path()).expect("open storage");
        (dir, storage)
    }

    #[test]
    fn open_and_close() {
        let (_dir, s) = temp_storage();
        drop(s);
    }

    #[test]
    fn put_get_delete() {
        let (_dir, s) = temp_storage();
        let key = b"hello";
        let value = b"world";

        assert!(!s.contains(Column::Metadata, key).unwrap());
        s.put(Column::Metadata, key, value).unwrap();
        assert!(s.contains(Column::Metadata, key).unwrap());
        assert_eq!(s.get(Column::Metadata, key).unwrap().unwrap(), value);

        s.delete(Column::Metadata, key).unwrap();
        assert!(!s.contains(Column::Metadata, key).unwrap());
    }

    #[test]
    fn get_missing_returns_none() {
        let (_dir, s) = temp_storage();
        assert!(s.get(Column::Blocks, b"nope").unwrap().is_none());
    }

    #[test]
    fn put_overwrites() {
        let (_dir, s) = temp_storage();
        s.put(Column::Metadata, b"k", b"v1").unwrap();
        s.put(Column::Metadata, b"k", b"v2").unwrap();
        assert_eq!(s.get(Column::Metadata, b"k").unwrap().unwrap(), b"v2");
    }

    #[test]
    fn columns_are_isolated() {
        let (_dir, s) = temp_storage();
        s.put(Column::Blocks, b"k", b"blocks").unwrap();
        s.put(Column::Transactions, b"k", b"txs").unwrap();
        assert_eq!(s.get(Column::Blocks, b"k").unwrap().unwrap(), b"blocks");
        assert_eq!(s.get(Column::Transactions, b"k").unwrap().unwrap(), b"txs");
    }

    #[test]
    fn batch_is_atomic() {
        let (_dir, s) = temp_storage();
        let mut b = Batch::new();
        b.put(Column::Blocks, b"block1", b"data1");
        b.put(Column::Metadata, b"tip", b"block1");
        s.write_batch(b).unwrap();

        assert_eq!(s.get(Column::Blocks, b"block1").unwrap().unwrap(), b"data1");
        assert_eq!(s.get(Column::Metadata, b"tip").unwrap().unwrap(), b"block1");
    }

    #[test]
    fn batch_with_delete() {
        let (_dir, s) = temp_storage();
        s.put(Column::Metadata, b"k", b"v").unwrap();

        let mut b = Batch::new();
        b.put(Column::Metadata, b"k2", b"v2");
        b.delete(Column::Metadata, b"k");
        s.write_batch(b).unwrap();

        assert!(s.get(Column::Metadata, b"k").unwrap().is_none());
        assert_eq!(s.get(Column::Metadata, b"k2").unwrap().unwrap(), b"v2");
    }

    #[test]
    fn persistence_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let s = Storage::open(dir.path()).unwrap();
            s.put(Column::Blocks, b"persist", b"yes").unwrap();
            s.flush().unwrap();
        }
        {
            let s = Storage::open(dir.path()).unwrap();
            assert_eq!(s.get(Column::Blocks, b"persist").unwrap().unwrap(), b"yes");
        }
    }

    #[test]
    fn empty_batch_is_ok() {
        let (_dir, s) = temp_storage();
        let b = Batch::new();
        assert!(b.is_empty());
        s.write_batch(b).unwrap();
    }
}
