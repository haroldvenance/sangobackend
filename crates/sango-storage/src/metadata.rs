//! Persistance des compteurs globaux du namespace `Metadata`.
//!
//! ## Clés canoniques
//!
//! Chaque entrée est identifiée par :
//!
//! ```text
//! [Namespace::Metadata.tag() || MetadataKey::X.tag()]
//! ```
//!
//! Ce sont les mêmes clés logiques que celles utilisées par le SMT de
//! `sango-state`. La persistance RocksDB n'influence pas la valeur du
//! `native_state_root`.

use sango_codec::{Decode, Encode};
use sango_primitives::Amount;
use sango_state::{MetadataKey, Namespace};
use sango_types::ChainTip;

use crate::column::Column;
use crate::db::Storage;
use crate::error::StorageError;

/// Construit la clé logique d'une entrée `Metadata`.
#[must_use]
pub fn metadata_key(key: MetadataKey) -> [u8; 2] {
    [Namespace::Metadata.tag(), key.tag()]
}

impl Storage {
    // --- total_burned -------------------------------------------------------

    /// Lit le cumul `total_burned` persisté.
    ///
    /// Retourne `None` si aucune entrée n'a été écrite.
    pub fn get_total_burned(&self) -> Result<Option<Amount>, StorageError> {
        let key = metadata_key(MetadataKey::TotalBurned);
        match self.get(Column::Metadata, &key)? {
            Some(bytes) => {
                let raw = u128::decode_exact(&bytes)?;
                Ok(Some(Amount::from_base_units(raw)))
            }
            None => Ok(None),
        }
    }

    /// Persiste `total_burned`.
    pub fn set_total_burned(&self, amount: Amount) -> Result<(), StorageError> {
        let key = metadata_key(MetadataKey::TotalBurned);
        let bytes = amount.base_units().encode_to_vec();
        self.put(Column::Metadata, &key, &bytes)
    }

    // --- total_gas_used -----------------------------------------------------

    /// Lit le cumul `total_gas_used` persisté.
    ///
    /// Retourne `None` si aucune entrée n'a été écrite.
    pub fn get_total_gas_used(&self) -> Result<Option<u64>, StorageError> {
        let key = metadata_key(MetadataKey::TotalGasUsed);
        match self.get(Column::Metadata, &key)? {
            Some(bytes) => Ok(Some(u64::decode_exact(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Persiste `total_gas_used`.
    pub fn set_total_gas_used(&self, gas: u64) -> Result<(), StorageError> {
        let key = metadata_key(MetadataKey::TotalGasUsed);
        let bytes = gas.encode_to_vec();
        self.put(Column::Metadata, &key, &bytes)
    }

    // --- chain_tip ----------------------------------------------------------

    /// Lit le `ChainTip` persisté.
    ///
    /// Retourne `None` si aucun bloc n'a encore été appliqué.
    pub fn get_chain_tip(&self) -> Result<Option<ChainTip>, StorageError> {
        let key = metadata_key(MetadataKey::ChainTip);
        match self.get(Column::Metadata, &key)? {
            Some(bytes) => Ok(Some(ChainTip::decode_exact(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Persiste le `ChainTip`.
    pub fn set_chain_tip(&self, tip: &ChainTip) -> Result<(), StorageError> {
        let key = metadata_key(MetadataKey::ChainTip);
        let bytes = tip.encode_to_vec();
        self.put(Column::Metadata, &key, &bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sango_primitives::{Hash32, Height};

    fn temp_storage() -> (tempfile::TempDir, Storage) {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        (dir, storage)
    }

    #[test]
    fn total_burned_absent_returns_none() {
        let (_dir, s) = temp_storage();
        assert!(s.get_total_burned().unwrap().is_none());
    }

    #[test]
    fn total_burned_roundtrip() {
        let (_dir, s) = temp_storage();
        let v = Amount::from_base_units(12_345);
        s.set_total_burned(v).unwrap();
        assert_eq!(s.get_total_burned().unwrap(), Some(v));
    }

    #[test]
    fn total_burned_overwrites() {
        let (_dir, s) = temp_storage();
        s.set_total_burned(Amount::from_base_units(1)).unwrap();
        s.set_total_burned(Amount::from_base_units(2)).unwrap();
        assert_eq!(
            s.get_total_burned().unwrap(),
            Some(Amount::from_base_units(2))
        );
    }

    #[test]
    fn total_gas_used_absent_returns_none() {
        let (_dir, s) = temp_storage();
        assert!(s.get_total_gas_used().unwrap().is_none());
    }

    #[test]
    fn total_gas_used_roundtrip() {
        let (_dir, s) = temp_storage();
        s.set_total_gas_used(21_000).unwrap();
        assert_eq!(s.get_total_gas_used().unwrap(), Some(21_000));
    }

    #[test]
    fn persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let s = Storage::open(dir.path()).unwrap();
            s.set_total_burned(Amount::from_base_units(999)).unwrap();
            s.set_total_gas_used(42).unwrap();
            s.flush().unwrap();
        }
        {
            let s = Storage::open(dir.path()).unwrap();
            assert_eq!(
                s.get_total_burned().unwrap(),
                Some(Amount::from_base_units(999))
            );
            assert_eq!(s.get_total_gas_used().unwrap(), Some(42));
        }
    }

    #[test]
    fn keys_are_isolated_from_other_columns() {
        let (_dir, s) = temp_storage();
        s.set_total_burned(Amount::from_base_units(1)).unwrap();
        let key = metadata_key(MetadataKey::TotalBurned);
        s.put(Column::Blocks, &key, b"garbage").unwrap();
        assert_eq!(
            s.get_total_burned().unwrap(),
            Some(Amount::from_base_units(1))
        );
    }

    #[test]
    fn metadata_key_format() {
        assert_eq!(
            metadata_key(MetadataKey::TotalBurned),
            [Namespace::Metadata.tag(), MetadataKey::TotalBurned.tag()]
        );
        assert_eq!(
            metadata_key(MetadataKey::TotalGasUsed),
            [Namespace::Metadata.tag(), MetadataKey::TotalGasUsed.tag()]
        );
        assert_eq!(
            metadata_key(MetadataKey::ChainTip),
            [Namespace::Metadata.tag(), MetadataKey::ChainTip.tag()]
        );
    }

    #[test]
    fn chain_tip_absent_returns_none() {
        let (_dir, s) = temp_storage();
        assert!(s.get_chain_tip().unwrap().is_none());
    }

    #[test]
    fn chain_tip_roundtrip() {
        let (_dir, s) = temp_storage();
        let tip = ChainTip {
            height: Height::new(5),
            block_hash: Hash32::from_bytes([0xab; 32]),
            base_fee: 100,
        };
        s.set_chain_tip(&tip).unwrap();
        assert_eq!(s.get_chain_tip().unwrap(), Some(tip));
    }

    #[test]
    fn chain_tip_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let tip = ChainTip {
            height: Height::new(10),
            block_hash: Hash32::from_bytes([0xcd; 32]),
            base_fee: 999,
        };
        {
            let s = Storage::open(dir.path()).unwrap();
            s.set_chain_tip(&tip).unwrap();
            s.flush().unwrap();
        }
        {
            let s = Storage::open(dir.path()).unwrap();
            assert_eq!(s.get_chain_tip().unwrap(), Some(tip));
        }
    }
}
