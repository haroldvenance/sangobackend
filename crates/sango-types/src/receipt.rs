//! Receipt et logs EVM.

use sango_codec::{CodecError, Decode, Decoder, Encode, Encoder};
use sango_primitives::{EvmAddress, Hash32};

/// Taille du bloom filter Ethereum-compatible (2048 bits = 256 bytes).
pub const LOGS_BLOOM_BYTES: usize = 256;

/// Nombre maximal de topics par log EVM.
pub const MAX_LOG_TOPICS: usize = 4;

/// Bloom filter 2048 bits, compatible Ethereum.
///
/// Le bit-setting suit la sémantique Ethereum : pour chaque valeur
/// (adresse ou topic), on calcule `Keccak256(valeur)` puis on positionne
/// 3 bits aux index `(m3[0]<<8|m3[1]) & 0x7FF`, `(m3[2]<<8|m3[3]) & 0x7FF`,
/// `(m3[4]<<8|m3[5]) & 0x7FF`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct LogsBloom([u8; LOGS_BLOOM_BYTES]);

impl LogsBloom {
    /// Bloom vide (tous les bits à zéro).
    pub const EMPTY: Self = Self([0u8; LOGS_BLOOM_BYTES]);

    /// Construit à partir d'un tableau brut.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; LOGS_BLOOM_BYTES]) -> Self {
        Self(bytes)
    }

    /// Vue empruntée sur les bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; LOGS_BLOOM_BYTES] {
        &self.0
    }

    /// Vrai si le bloom est vide.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.iter().all(|b| *b == 0)
    }

    /// Ajoute un élément (adresse ou topic) au bloom.
    pub fn insert_value(&mut self, value: &[u8]) {
        let m3 = sango_crypto::keccak256(value);
        for i in [0usize, 2, 4] {
            let bit_index =
                (((m3.as_bytes()[i] as u16) << 8) | (m3.as_bytes()[i + 1] as u16)) & 0x7FF;
            let byte_index = 255 - (bit_index / 8) as usize;
            let bit_in_byte = (bit_index % 8) as u8;
            self.0[byte_index] |= 1 << bit_in_byte;
        }
    }

    /// Construit un bloom à partir d'une liste de logs.
    #[must_use]
    pub fn from_logs(logs: &[EvmLog]) -> Self {
        let mut bloom = Self::EMPTY;
        for log in logs {
            bloom.insert_value(log.address.as_bytes());
            for topic in &log.topics {
                bloom.insert_value(topic.as_bytes());
            }
        }
        bloom
    }
}

impl Default for LogsBloom {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl Encode for LogsBloom {
    fn encode(&self, enc: &mut Encoder) {
        enc.write_raw(&self.0);
    }
}

impl Decode for LogsBloom {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self(dec.read_fixed::<LOGS_BLOOM_BYTES>()?))
    }
}

/// Log EVM (LOG0 à LOG4).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvmLog {
    /// Contrat ayant émis le log.
    pub address: EvmAddress,
    /// Topics indexés (0 à 4).
    pub topics: Vec<Hash32>,
    /// Données non indexées.
    pub data: Vec<u8>,
}

impl Encode for EvmLog {
    fn encode(&self, enc: &mut Encoder) {
        self.address.encode(enc);
        self.topics.encode(enc);
        self.data.encode(enc);
    }
}

impl Decode for EvmLog {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            address: EvmAddress::decode(dec)?,
            topics: Vec::<Hash32>::decode(dec)?,
            data: Vec::<u8>::decode(dec)?,
        })
    }
}

/// Statut d'un receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ReceiptStatus {
    /// Échec d'exécution (`0`).
    Failure,
    /// Succès (`1`).
    Success,
}

impl ReceiptStatus {
    /// Tag canonique.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            ReceiptStatus::Failure => 0,
            ReceiptStatus::Success => 1,
        }
    }

    /// Parse un tag canonique.
    pub fn from_tag(tag: u8) -> Result<Self, CodecError> {
        match tag {
            0 => Ok(ReceiptStatus::Failure),
            1 => Ok(ReceiptStatus::Success),
            other => Err(CodecError::InvalidTag { tag: other }),
        }
    }
}

impl Encode for ReceiptStatus {
    fn encode(&self, enc: &mut Encoder) {
        enc.write_u8(self.tag());
    }
}

impl Decode for ReceiptStatus {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Self::from_tag(dec.read_u8()?)
    }
}

/// Receipt canonique Sango V1 (Freeze, section 9).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Receipt {
    /// Hash de la transaction associée.
    pub tx_hash: Hash32,
    /// Statut d'exécution.
    pub status: ReceiptStatus,
    /// Gas cumulé depuis le début du bloc.
    pub cumulative_gas_used: u64,
    /// Gas consommé par cette transaction.
    pub gas_used: u64,
    /// Adresse du contrat créé, si applicable.
    pub contract_address: Option<EvmAddress>,
    /// Bloom des logs.
    pub logs_bloom: LogsBloom,
    /// Logs émis.
    pub logs: Vec<EvmLog>,
}

impl Encode for Receipt {
    fn encode(&self, enc: &mut Encoder) {
        self.tx_hash.encode(enc);
        self.status.encode(enc);
        self.cumulative_gas_used.encode(enc);
        self.gas_used.encode(enc);
        self.contract_address.encode(enc);
        self.logs_bloom.encode(enc);
        self.logs.encode(enc);
    }
}

impl Decode for Receipt {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            tx_hash: Hash32::decode(dec)?,
            status: ReceiptStatus::decode(dec)?,
            cumulative_gas_used: u64::decode(dec)?,
            gas_used: u64::decode(dec)?,
            contract_address: Option::<EvmAddress>::decode(dec)?,
            logs_bloom: LogsBloom::decode(dec)?,
            logs: Vec::<EvmLog>::decode(dec)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log(address_byte: u8, topics: Vec<Hash32>, data: Vec<u8>) -> EvmLog {
        EvmLog {
            address: EvmAddress::from_bytes([address_byte; 20]),
            topics,
            data,
        }
    }

    #[test]
    fn empty_bloom_is_empty() {
        assert!(LogsBloom::EMPTY.is_empty());
    }

    #[test]
    fn empty_bloom_roundtrip() {
        let b = LogsBloom::EMPTY;
        let bytes = b.encode_to_vec();
        assert_eq!(bytes.len(), LOGS_BLOOM_BYTES);
        assert_eq!(LogsBloom::decode_exact(&bytes).unwrap(), b);
    }

    #[test]
    fn insert_value_sets_bits() {
        let mut bloom = LogsBloom::EMPTY;
        bloom.insert_value(b"hello");
        assert!(!bloom.is_empty());
    }

    #[test]
    fn from_logs_matches_manual_insert() {
        let l = log(0xaa, vec![Hash32::from_bytes([0x11; 32])], vec![1, 2, 3]);
        let bloom_auto = LogsBloom::from_logs(std::slice::from_ref(&l));

        let mut bloom_manual = LogsBloom::EMPTY;
        bloom_manual.insert_value(l.address.as_bytes());
        for t in &l.topics {
            bloom_manual.insert_value(t.as_bytes());
        }
        assert_eq!(bloom_auto, bloom_manual);
    }

    #[test]
    fn from_logs_is_deterministic() {
        let l1 = log(0xaa, vec![Hash32::from_bytes([0x11; 32])], vec![]);
        let l2 = log(0xbb, vec![], vec![0xde, 0xad]);
        let a = LogsBloom::from_logs(&[l1.clone(), l2.clone()]);
        let b = LogsBloom::from_logs(&[l1, l2]);
        assert_eq!(a, b);
    }

    #[test]
    fn receipt_status_tag_roundtrip() {
        for s in [ReceiptStatus::Failure, ReceiptStatus::Success] {
            assert_eq!(ReceiptStatus::from_tag(s.tag()).unwrap(), s);
        }
        assert!(ReceiptStatus::from_tag(2).is_err());
    }

    #[test]
    fn receipt_roundtrip() {
        let l = log(0xaa, vec![Hash32::from_bytes([0x11; 32])], vec![1, 2, 3]);
        let r = Receipt {
            tx_hash: Hash32::from_bytes([0x42; 32]),
            status: ReceiptStatus::Success,
            cumulative_gas_used: 21_000,
            gas_used: 21_000,
            contract_address: None,
            logs_bloom: LogsBloom::from_logs(std::slice::from_ref(&l)),
            logs: vec![l],
        };
        let bytes = r.encode_to_vec();
        let decoded = Receipt::decode_exact(&bytes).unwrap();
        assert_eq!(decoded, r);
    }

    #[test]
    fn receipt_with_contract_address() {
        let r = Receipt {
            tx_hash: Hash32::ZERO,
            status: ReceiptStatus::Success,
            cumulative_gas_used: 100,
            gas_used: 100,
            contract_address: Some(EvmAddress::from_bytes([0xcc; 20])),
            logs_bloom: LogsBloom::EMPTY,
            logs: Vec::new(),
        };
        let bytes = r.encode_to_vec();
        let decoded = Receipt::decode_exact(&bytes).unwrap();
        assert_eq!(
            decoded.contract_address,
            Some(EvmAddress::from_bytes([0xcc; 20]))
        );
    }

    #[test]
    fn receipt_empty_logs() {
        let r = Receipt {
            tx_hash: Hash32::ZERO,
            status: ReceiptStatus::Failure,
            cumulative_gas_used: 0,
            gas_used: 0,
            contract_address: None,
            logs_bloom: LogsBloom::EMPTY,
            logs: Vec::new(),
        };
        let bytes = r.encode_to_vec();
        let decoded = Receipt::decode_exact(&bytes).unwrap();
        assert_eq!(decoded, r);
    }
}
