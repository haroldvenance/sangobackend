//! Bloc Sango V1.

use sango_codec::{CodecError, Decode, Decoder, Encode, Encoder};
use sango_primitives::Hash32;

use crate::header::BlockHeader;
use crate::transaction::Transaction;

/// Bloc Sango V1 (Freeze, section 26).
///
/// Encodage canonique :
///
/// ```text
/// canonical(BlockHeader) || u32 transaction_count || transactions...
/// ```
///
/// Le hash du bloc est **exactement** le hash du header. Le certificat de
/// commit n'est pas inclus dans le hash (Freeze, section 19), ce qui évite
/// une dépendance circulaire.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Block {
    /// En-tête du bloc.
    pub header: BlockHeader,
    /// Transactions du bloc, dans leur ordre canonique.
    pub transactions: Vec<Transaction>,
}

impl Block {
    /// Hash du bloc (= hash du header).
    #[must_use]
    pub fn hash(&self) -> Hash32 {
        self.header.hash()
    }

    /// Nombre de transactions.
    #[must_use]
    pub fn tx_count(&self) -> usize {
        self.transactions.len()
    }
}

impl Encode for Block {
    fn encode(&self, enc: &mut Encoder) {
        self.header.encode(enc);
        self.transactions.encode(enc);
    }
}

impl Decode for Block {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            header: BlockHeader::decode(dec)?,
            transactions: Vec::<Transaction>::decode(dec)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::TxKind;
    use sango_primitives::{Amount, ChainId32, Epoch, Height, NativeAddress, Round, Signature};

    fn header() -> BlockHeader {
        BlockHeader {
            version: 1,
            chain_id: ChainId32::from_bytes([0x11; 32]),
            epoch: Epoch::new(0),
            height: Height::new(1),
            round: Round::new(0),
            previous_block_hash: Hash32::from_bytes([0x22; 32]),
            timestamp: 1_700_000_000,
            proposer_address: NativeAddress::from_bytes([0x33; 20]),
            transaction_root: Hash32::from_bytes([0x44; 32]),
            state_root: Hash32::from_bytes([0x55; 32]),
            receipt_root: Hash32::from_bytes([0x66; 32]),
            gas_used: 0,
            gas_limit: 30_000_000,
            base_fee: 1,
        }
    }

    fn tx(nonce: u64) -> Transaction {
        Transaction {
            version: 1,
            chain_id: ChainId32::from_bytes([0x11; 32]),
            nonce,
            sender: NativeAddress::from_bytes([0xaa; 20]),
            public_key: None,
            gas_limit: 21_000,
            max_fee: 20,
            priority_fee: 2,
            value: Amount::from_base_units(1_000),
            tx_kind: TxKind::Transfer,
            recipient: Some(NativeAddress::from_bytes([0xbb; 20])),
            data: Vec::new(),
            signature: Signature::ZERO,
        }
    }

    #[test]
    fn empty_block_roundtrip() {
        let b = Block {
            header: header(),
            transactions: Vec::new(),
        };
        let bytes = b.encode_to_vec();
        let decoded = Block::decode_exact(&bytes).unwrap();
        assert_eq!(decoded, b);
    }

    #[test]
    fn block_with_transactions_roundtrip() {
        let b = Block {
            header: header(),
            transactions: vec![tx(0), tx(1), tx(2)],
        };
        let bytes = b.encode_to_vec();
        let decoded = Block::decode_exact(&bytes).unwrap();
        assert_eq!(decoded, b);
    }

    #[test]
    fn block_hash_equals_header_hash() {
        let b = Block {
            header: header(),
            transactions: vec![tx(0)],
        };
        assert_eq!(b.hash(), b.header.hash());
    }

    #[test]
    fn tx_count() {
        let b = Block {
            header: header(),
            transactions: vec![tx(0), tx(1)],
        };
        assert_eq!(b.tx_count(), 2);
    }

    #[test]
    fn encoding_length_is_header_plus_txs() {
        let b = Block {
            header: header(),
            transactions: Vec::new(),
        };
        // header = 248 bytes, tx count = 4 bytes (u32 LE) → 252
        assert_eq!(b.encode_to_vec().len(), 252);
    }
}
