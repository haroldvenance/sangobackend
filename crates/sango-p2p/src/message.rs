//! Messages réseau Sango.
//!
//! Tous les messages sont encodés avec le codec canonique Sango
//! (`sango-codec`). Aucun protobuf, aucun JSON.
//!
//! ## Format
//!
//! ```text
//! u8 message_type || canonical(payload)
//! ```
//!
//! Tags :
//!
//! - `0x01` : `Proposal`
//! - `0x02` : `Prevote`
//! - `0x03` : `Precommit`
//! - `0x04` : `Transaction`
//! - `0x05` : `Block`

use sango_codec::{CodecError, Decode, Decoder, Encode, Encoder};
use sango_types::{Block, Precommit, Prevote, Proposal, Transaction};

/// Tag d'un message réseau.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum MessageType {
    /// Proposition de bloc.
    Proposal = 0x01,
    /// Vote prevote.
    Prevote = 0x02,
    /// Vote precommit.
    Precommit = 0x03,
    /// Transaction mempool.
    Transaction = 0x04,
    /// Bloc (pour la synchronisation).
    Block = 0x05,
}

impl MessageType {
    /// Parse un tag.
    pub fn from_tag(tag: u8) -> Result<Self, CodecError> {
        match tag {
            0x01 => Ok(MessageType::Proposal),
            0x02 => Ok(MessageType::Prevote),
            0x03 => Ok(MessageType::Precommit),
            0x04 => Ok(MessageType::Transaction),
            0x05 => Ok(MessageType::Block),
            other => Err(CodecError::InvalidTag { tag: other }),
        }
    }
}

/// Message réseau canonique.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NetworkMessage {
    /// Proposition de bloc.
    Proposal(Box<Proposal>),
    /// Vote prevote.
    Prevote(Prevote),
    /// Vote precommit.
    Precommit(Precommit),
    /// Transaction du mempool.
    Transaction(Transaction),
    /// Bloc complet (synchronisation).
    Block(Box<Block>),
}

impl NetworkMessage {
    /// Type du message.
    #[must_use]
    pub fn message_type(&self) -> MessageType {
        match self {
            NetworkMessage::Proposal(_) => MessageType::Proposal,
            NetworkMessage::Prevote(_) => MessageType::Prevote,
            NetworkMessage::Precommit(_) => MessageType::Precommit,
            NetworkMessage::Transaction(_) => MessageType::Transaction,
            NetworkMessage::Block(_) => MessageType::Block,
        }
    }
}

impl Encode for NetworkMessage {
    fn encode(&self, enc: &mut Encoder) {
        enc.write_u8(self.message_type() as u8);
        match self {
            NetworkMessage::Proposal(p) => (**p).encode(enc),
            NetworkMessage::Prevote(v) => v.encode(enc),
            NetworkMessage::Precommit(c) => c.encode(enc),
            NetworkMessage::Transaction(tx) => tx.encode(enc),
            NetworkMessage::Block(b) => (**b).encode(enc),
        }
    }
}

impl Decode for NetworkMessage {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let tag = dec.read_u8()?;
        let mt = MessageType::from_tag(tag)?;
        Ok(match mt {
            MessageType::Proposal => NetworkMessage::Proposal(Box::new(Proposal::decode(dec)?)),
            MessageType::Prevote => NetworkMessage::Prevote(Prevote::decode(dec)?),
            MessageType::Precommit => NetworkMessage::Precommit(Precommit::decode(dec)?),
            MessageType::Transaction => NetworkMessage::Transaction(Transaction::decode(dec)?),
            MessageType::Block => NetworkMessage::Block(Box::new(Block::decode(dec)?)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sango_primitives::{ChainId32, Epoch, Height, NativeAddress, Round, Signature};
    use sango_types::TxKind;

    fn dummy_transfer() -> Transaction {
        Transaction {
            version: 1,
            chain_id: ChainId32::from_bytes([0x11; 32]),
            nonce: 0,
            sender: NativeAddress::from_bytes([0xaa; 20]),
            public_key: None,
            gas_limit: 21_000,
            max_fee: 20,
            priority_fee: 2,
            value: sango_primitives::Amount::from_base_units(100),
            tx_kind: TxKind::Transfer,
            recipient: Some(NativeAddress::from_bytes([0xbb; 20])),
            data: Vec::new(),
            signature: Signature::ZERO,
        }
    }

    fn dummy_prevote() -> Prevote {
        Prevote {
            chain_id: ChainId32::from_bytes([0x11; 32]),
            epoch: Epoch::new(0),
            height: Height::new(1),
            round: Round::new(0),
            block_hash: None,
            validator_address: NativeAddress::from_bytes([0xaa; 20]),
            validator_signature: Signature::ZERO,
        }
    }

    #[test]
    fn message_type_tags_roundtrip() {
        for t in [
            MessageType::Proposal,
            MessageType::Prevote,
            MessageType::Precommit,
            MessageType::Transaction,
            MessageType::Block,
        ] {
            assert_eq!(MessageType::from_tag(t as u8).unwrap(), t);
        }
        assert!(MessageType::from_tag(0x00).is_err());
    }

    #[test]
    fn transfer_message_roundtrip() {
        let msg = NetworkMessage::Transaction(dummy_transfer());
        let bytes = msg.encode_to_vec();
        let decoded = NetworkMessage::decode_exact(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn prevote_message_roundtrip() {
        let msg = NetworkMessage::Prevote(dummy_prevote());
        let bytes = msg.encode_to_vec();
        assert_eq!(NetworkMessage::decode_exact(&bytes).unwrap(), msg);
    }

    #[test]
    fn message_starts_with_correct_tag() {
        let msg = NetworkMessage::Prevote(dummy_prevote());
        let bytes = msg.encode_to_vec();
        assert_eq!(bytes[0], MessageType::Prevote as u8);
    }
}
