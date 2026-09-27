//! Index secondaires des transactions.
//!
//! ## Rôle
//!
//! Permet deux requêtes qui ne sont pas possibles directement à partir
//! de `Column::Transactions` :
//!
//! 1. **Localiser une tx** : à partir d'un `tx_hash`, retrouver la
//!    hauteur, le hash de bloc et l'index dans le bloc.
//! 2. **Lister les txs d'une adresse** : à partir d'une `NativeAddress`,
//!    paginer les transactions natives qu'elle a émises.
//!
//! ## Dépendance
//!
//! [`TxLocation`] et les constantes `TX_TAG_*` vivent dans
//! [`sango_rpc::backend`] : le trait `RpcBackend` doit les voir sans
//! que `sango-rpc` ne dépende de `sango-node`. On les réexporte ici
//! pour commodité.
//!
//! ## Colonnes RocksDB
//!
//! ### `TxLocations`
//!
//! ```text
//! clé    = tx_hash (32 bytes)
//! valeur = TxLocation::encode()  (45 bytes)
//! ```
//!
//! ### `TxBySender`
//!
//! ```text
//! clé    = sender(20) || height_be(8) || tx_index_be(4)   (32 bytes)
//! valeur = tx_hash (32 bytes)
//! ```
//!
//! Le tri byte-lex de RocksDB sur cette clé équivaut à un tri par
//! `(sender, height, tx_index)`. Pour paginer « plus récent d'abord »,
//! on itère à l'envers sur le préfixe `sender`.
//!
//! **Important** : seules les txs `Tx::Native` sont indexées par
//! sender. Les txs EVM ont un sender EVM (`EvmAddress`) et un
//! namespace RPC distinct (`eth_*`) qui sera ajouté plus tard.

use sango_primitives::{Hash32, NativeAddress};
use sango_storage::{Batch, Column};
use sango_types::Tx;

pub use sango_rpc::backend::{TxLocation, TX_LOCATION_ENCODED_LEN, TX_TAG_EVM, TX_TAG_NATIVE};

/// Longueur d'une clé `TxBySender`.
pub const TX_BY_SENDER_KEY_LEN: usize = 32;

/// Construit la clé `TxBySender`.
///
/// Format : `sender(20) || height_be(8) || tx_index_be(4)`.
#[must_use]
pub fn tx_by_sender_key(sender: &NativeAddress, height: u64, tx_index: u32) -> [u8; 32] {
    let mut k = [0u8; TX_BY_SENDER_KEY_LEN];
    k[..20].copy_from_slice(sender.as_bytes());
    k[20..28].copy_from_slice(&height.to_be_bytes());
    k[28..32].copy_from_slice(&tx_index.to_be_bytes());
    k
}

/// Décode une clé `TxBySender`.
///
/// Retourne `(sender, height, tx_index)`, ou `None` si la longueur est
/// incorrecte.
#[must_use]
pub fn decode_tx_by_sender_key(key: &[u8]) -> Option<(NativeAddress, u64, u32)> {
    if key.len() != TX_BY_SENDER_KEY_LEN {
        return None;
    }
    let mut s = [0u8; 20];
    s.copy_from_slice(&key[..20]);
    let mut h = [0u8; 8];
    h.copy_from_slice(&key[20..28]);
    let mut ti = [0u8; 4];
    ti.copy_from_slice(&key[28..32]);
    Some((
        NativeAddress::from_bytes(s),
        u64::from_be_bytes(h),
        u32::from_be_bytes(ti),
    ))
}

/// Écrit l'index d'une transaction dans un `Batch`.
///
/// ## Comportement
///
/// - Écrit toujours dans `TxLocations`.
/// - Écrit dans `TxBySender` **uniquement** pour les txs natives.
///
/// ## Idempotence
///
/// `apply_block` n'écrit jamais deux fois le même `tx_hash` (un bloc
/// appliqué est unique par hash). Un `put` sur une clé existante est
/// un remplacement, pas une erreur.
pub fn write_tx_index(batch: &mut Batch, tx: &Tx, height: u64, block_hash: Hash32, tx_index: u32) {
    let tx_hash = tx.hash();
    let tag = match tx {
        Tx::Native(_) => TX_TAG_NATIVE,
        Tx::Evm(_) => TX_TAG_EVM,
    };
    let location = TxLocation {
        height,
        block_hash,
        tx_index,
        tag,
    };
    batch.put(Column::TxLocations, tx_hash.as_bytes(), location.encode());

    if let Tx::Native(native) = tx {
        let key = tx_by_sender_key(&native.sender, height, tx_index);
        batch.put(Column::TxBySender, key, tx_hash.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sango_primitives::{Amount, ChainId32, Signature};
    use sango_storage::Storage;
    use sango_types::{Transaction, TxKind};

    fn addr(b: u8) -> NativeAddress {
        NativeAddress::from_bytes([b; 20])
    }

    fn hash(b: u8) -> Hash32 {
        Hash32::from_bytes([b; 32])
    }

    fn sample_native(nonce: u64) -> Transaction {
        Transaction {
            version: 1,
            chain_id: ChainId32::from_bytes([0x11; 32]),
            nonce,
            sender: addr(0xaa),
            public_key: None,
            gas_limit: 21_000,
            max_fee: 20,
            priority_fee: 2,
            value: Amount::from_base_units(1_000),
            tx_kind: TxKind::Transfer,
            recipient: Some(addr(0xbb)),
            data: Vec::new(),
            signature: Signature::ZERO,
        }
    }

    // --- TxLocation (délégué à sango-rpc) ---------------------------------

    #[test]
    fn tx_location_encode_length_is_fixed() {
        let loc = TxLocation {
            height: 42,
            block_hash: hash(0xab),
            tx_index: 7,
            tag: TX_TAG_NATIVE,
        };
        assert_eq!(loc.encode().len(), TX_LOCATION_ENCODED_LEN);
    }

    #[test]
    fn tx_location_roundtrip() {
        let loc = TxLocation {
            height: 1_234_567_890,
            block_hash: hash(0xcd),
            tx_index: 42,
            tag: TX_TAG_EVM,
        };
        let bytes = loc.encode();
        let decoded = TxLocation::decode(&bytes).unwrap();
        assert_eq!(decoded, loc);
    }

    #[test]
    fn tx_location_decode_rejects_bad_length() {
        for bad_len in [0, 44, 46, 100] {
            assert!(TxLocation::decode(&vec![0u8; bad_len]).is_none());
        }
    }

    #[test]
    fn tx_location_tags_are_distinct() {
        assert_ne!(TX_TAG_NATIVE, TX_TAG_EVM);
        assert_eq!(TX_TAG_NATIVE, 0x01);
        assert_eq!(TX_TAG_EVM, 0x02);
    }

    // --- tx_by_sender_key -------------------------------------------------

    #[test]
    fn tx_by_sender_key_length_is_32() {
        let key = tx_by_sender_key(&addr(0xaa), 42, 7);
        assert_eq!(key.len(), TX_BY_SENDER_KEY_LEN);
    }

    #[test]
    fn tx_by_sender_key_roundtrip() {
        let sender = addr(0xaa);
        let key = tx_by_sender_key(&sender, 1_000_000, 12);
        let (decoded_sender, h, ti) = decode_tx_by_sender_key(&key).unwrap();
        assert_eq!(decoded_sender, sender);
        assert_eq!(h, 1_000_000);
        assert_eq!(ti, 12);
    }

    #[test]
    fn tx_by_sender_key_bad_length_returns_none() {
        assert!(decode_tx_by_sender_key(&[0u8; 31]).is_none());
        assert!(decode_tx_by_sender_key(&[0u8; 33]).is_none());
    }

    /// Le tri byte-lex des clés doit être équivalent au tri
    /// `(sender, height, tx_index)` croissant.
    #[test]
    fn tx_by_sender_key_sorts_lexicographically() {
        let sender_a = addr(0x01);
        let sender_b = addr(0x02);

        let mut keys = vec![
            tx_by_sender_key(&sender_b, 1, 0),
            tx_by_sender_key(&sender_a, 5, 0),
            tx_by_sender_key(&sender_a, 2, 0),
            tx_by_sender_key(&sender_b, 1, 1),
            tx_by_sender_key(&sender_a, 2, 3),
        ];
        keys.sort();

        let expected = vec![
            tx_by_sender_key(&sender_a, 2, 0),
            tx_by_sender_key(&sender_a, 2, 3),
            tx_by_sender_key(&sender_a, 5, 0),
            tx_by_sender_key(&sender_b, 1, 0),
            tx_by_sender_key(&sender_b, 1, 1),
        ];
        assert_eq!(keys, expected);
    }

    // --- write_tx_index + Storage ----------------------------------------

    fn temp_storage() -> (tempfile::TempDir, Storage) {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        (dir, storage)
    }

    #[test]
    fn write_tx_index_writes_location() {
        let (_dir, storage) = temp_storage();
        let tx = Tx::Native(sample_native(0));
        let tx_hash = tx.hash();

        let mut batch = Batch::new();
        write_tx_index(&mut batch, &tx, 10, hash(0xcc), 3);
        storage.write_batch(batch).unwrap();

        let loc_bytes = storage
            .get(Column::TxLocations, tx_hash.as_bytes())
            .unwrap()
            .unwrap();
        let loc = TxLocation::decode(&loc_bytes).unwrap();
        assert_eq!(loc.height, 10);
        assert_eq!(loc.block_hash, hash(0xcc));
        assert_eq!(loc.tx_index, 3);
        assert_eq!(loc.tag, TX_TAG_NATIVE);
    }

    #[test]
    fn write_tx_index_writes_sender_entry_for_native() {
        let (_dir, storage) = temp_storage();
        let tx = Tx::Native(sample_native(0));
        let tx_hash = tx.hash();

        let mut batch = Batch::new();
        write_tx_index(&mut batch, &tx, 10, hash(0xcc), 3);
        storage.write_batch(batch).unwrap();

        let key = tx_by_sender_key(&addr(0xaa), 10, 3);
        let stored_hash = storage.get(Column::TxBySender, &key).unwrap().unwrap();
        assert_eq!(stored_hash, tx_hash.as_bytes());
    }

    #[test]
    fn write_tx_index_does_not_write_sender_for_evm() {
        use sango_primitives::{EvmAddress, U256};
        use sango_types::{EvmAccessList, EvmTx};

        let evm = EvmTx::Eip1559 {
            chain_id: 7777,
            nonce: 0,
            max_priority_fee_per_gas: U256::from(1u64),
            max_fee_per_gas: U256::from(100u64),
            gas_limit: 21_000,
            to: Some(EvmAddress::from_bytes([0xcc; 20])),
            value: U256::ZERO,
            data: Vec::new(),
            access_list: EvmAccessList::default(),
            y_parity: 0,
            r: U256::from(1u64),
            s: U256::from(1u64),
        };
        let tx = Tx::Evm(evm);
        let tx_hash = tx.hash();

        let (_dir, storage) = temp_storage();
        let mut batch = Batch::new();
        write_tx_index(&mut batch, &tx, 10, hash(0xcc), 3);
        storage.write_batch(batch).unwrap();

        let loc_bytes = storage
            .get(Column::TxLocations, tx_hash.as_bytes())
            .unwrap()
            .unwrap();
        let loc = TxLocation::decode(&loc_bytes).unwrap();
        assert_eq!(loc.tag, TX_TAG_EVM);

        let all_senders = storage.iter_column(Column::TxBySender).unwrap();
        assert!(all_senders.is_empty());
    }
}
