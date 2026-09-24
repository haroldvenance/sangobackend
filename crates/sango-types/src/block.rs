//! Bloc Sango V1.

use sango_codec::{CodecError, Decode, Decoder, Encode, Encoder};
use sango_primitives::Hash32;

use crate::evidence::Evidence;
use crate::header::BlockHeader;
use crate::tx::Tx;

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
    /// Evidences (double-sign) à appliquer avant les transactions.
    ///
    /// Chaque evidence déclenche un slashing déterministe. L'ordre est
    /// canonique et fait partie du consensus.
    pub evidences: Vec<Evidence>,
    /// Transactions du bloc (natives et/ou EVM), dans leur ordre
    /// canonique.
    ///
    /// Depuis 4c.3.1b, ce champ est hétérogène : il peut contenir des
    /// [`Tx::Native`] (transaction Sango Ed25519) et des [`Tx::Evm`]
    /// (typed-transaction Ethereum secp256k1). Le codec du bloc écrit
    /// un discriminant Sango (`0x01` / `0x02`) devant chaque entrée,
    /// indépendant des types Ethereum typés.
    pub transactions: Vec<Tx>,
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
        self.evidences.encode(enc);
        self.transactions.encode(enc);
    }
}

impl Decode for Block {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            header: BlockHeader::decode(dec)?,
            evidences: Vec::<Evidence>::decode(dec)?,
            transactions: Vec::<Tx>::decode(dec)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{Transaction, TxKind};
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

    fn tx(nonce: u64) -> Tx {
        Tx::Native(Transaction {
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
        })
    }

    #[test]
    fn empty_block_roundtrip() {
        let b = Block {
            header: header(),
            evidences: Vec::new(),
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
            evidences: Vec::new(),
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
            evidences: Vec::new(),
            transactions: vec![tx(0)],
        };
        assert_eq!(b.hash(), b.header.hash());
    }

    #[test]
    fn tx_count() {
        let b = Block {
            header: header(),
            evidences: Vec::new(),
            transactions: vec![tx(0), tx(1)],
        };
        assert_eq!(b.tx_count(), 2);
    }

    #[test]
    fn block_with_evidence_roundtrip() {
        use crate::evidence::{ConsensusMessage, ConsensusMessageType, EvidenceType};
        use sango_primitives::{Epoch, Signature};

        let ev = crate::evidence::Evidence {
            version: 1,
            evidence_type: EvidenceType::DoublePrevote,
            chain_id: ChainId32::from_bytes([0x11; 32]),
            epoch: Epoch::new(0),
            height: Height::new(1),
            round: Round::new(0),
            validator_address: NativeAddress::from_bytes([0xaa; 20]),
            message_1: ConsensusMessage {
                message_type: ConsensusMessageType::Prevote,
                canonical_payload: vec![1, 2, 3],
                signature: Signature::ZERO,
            },
            message_2: ConsensusMessage {
                message_type: ConsensusMessageType::Prevote,
                canonical_payload: vec![4, 5, 6],
                signature: Signature::ZERO,
            },
        };
        let b = Block {
            header: header(),
            evidences: vec![ev],
            transactions: Vec::new(),
        };
        let bytes = b.encode_to_vec();
        let decoded = Block::decode_exact(&bytes).unwrap();
        assert_eq!(decoded, b);
    }

    #[test]
    fn encoding_length_is_header_plus_txs() {
        let b = Block {
            header: header(),
            evidences: Vec::new(),
            transactions: Vec::new(),
        };
        // header = 248 + evidences count (4) + tx count (4) = 256
        assert_eq!(b.encode_to_vec().len(), 256);
    }
}
