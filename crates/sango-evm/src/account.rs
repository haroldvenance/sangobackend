//! Encodage / décodage RLP Ethereum d'un [`EvmAccount`].
//!
//! ## Formule normative (Ethereum Yellow Paper, section 4.1)
//!
//! ```text
//! account_rlp = RLP([nonce, balance, storage_root, code_hash])
//! ```
//!
//! Règles RLP appliquées :
//!
//! - **nonce** (`u64`) : byte string big-endian **minimal**, sans zéros de
//!   tête ; `0` est encodé comme byte string vide (`0x80`).
//! - **balance** (`U256`) : idem.
//! - **storage_root** : 32 bytes bruts (hash Keccak).
//! - **code_hash** : 32 bytes bruts.
//!
//! Ce sont **exactement** les règles Ethereum. Aucune variante Sango.

use rlp::{Rlp, RlpStream};
use sango_primitives::{Hash32, U256};
use sango_types::EvmAccount;

use crate::error::EvmError;

/// `Keccak256(&[])` — hash du code vide (Ethereum).
///
/// Constante normative. Égale à
/// `c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470`.
pub fn empty_code_hash() -> Hash32 {
    sango_types::empty_code_hash()
}

/// Encode un [`EvmAccount`] en RLP Ethereum canonique.
#[must_use]
pub fn encode_account(acc: &EvmAccount) -> Vec<u8> {
    let mut s = RlpStream::new_list(4);
    append_u64_minimal(&mut s, acc.nonce);
    append_u256_minimal(&mut s, acc.balance);
    append_hash32(&mut s, &acc.storage_root);
    append_hash32(&mut s, &acc.code_hash);
    s.out().to_vec()
}

/// Décode un [`EvmAccount`] depuis son RLP Ethereum canonique.
pub fn decode_account(bytes: &[u8]) -> Result<EvmAccount, EvmError> {
    let rlp = Rlp::new(bytes);
    if !rlp.is_list() {
        return Err(EvmError::InvalidAccountRlp);
    }
    if rlp.item_count().map_err(|_| EvmError::MalformedRlp)? != 4 {
        return Err(EvmError::InvalidAccountRlp);
    }
    let nonce = decode_u64(&rlp.at(0).map_err(|_| EvmError::MalformedRlp)?, "nonce")?;
    let balance = decode_u256(&rlp.at(1).map_err(|_| EvmError::MalformedRlp)?)?;
    let storage_root = decode_hash32(&rlp.at(2).map_err(|_| EvmError::MalformedRlp)?)?;
    let code_hash = decode_hash32(&rlp.at(3).map_err(|_| EvmError::MalformedRlp)?)?;
    Ok(EvmAccount {
        nonce,
        balance,
        storage_root,
        code_hash,
    })
}

// --- Helpers RLP (partagés avec `storage.rs`) ------------------------------

pub(crate) fn append_u64_minimal(s: &mut RlpStream, v: u64) {
    if v == 0 {
        s.append_empty_data();
        return;
    }
    let bytes = v.to_be_bytes();
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(8);
    let slice: &[u8] = &bytes[start..];
    s.append(&slice);
}

pub(crate) fn append_u256_minimal(s: &mut RlpStream, v: U256) {
    if v == U256::ZERO {
        s.append_empty_data();
        return;
    }
    let bytes = v.to_be_bytes::<32>();
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(32);
    let slice: &[u8] = &bytes[start..];
    s.append(&slice);
}

pub(crate) fn append_hash32(s: &mut RlpStream, h: &Hash32) {
    let bytes: &[u8] = h.as_bytes();
    s.append(&bytes);
}

pub(crate) fn decode_u64(rlp: &Rlp, field: &'static str) -> Result<u64, EvmError> {
    let bytes = rlp.data().map_err(|_| EvmError::MalformedRlp)?;
    if bytes.len() > 8 {
        return Err(EvmError::IntegerOverflow { field });
    }
    let mut buf = [0u8; 8];
    buf[8 - bytes.len()..].copy_from_slice(bytes);
    Ok(u64::from_be_bytes(buf))
}

pub(crate) fn decode_u256(rlp: &Rlp) -> Result<U256, EvmError> {
    let bytes = rlp.data().map_err(|_| EvmError::MalformedRlp)?;
    if bytes.len() > 32 {
        return Err(EvmError::IntegerOverflow { field: "u256" });
    }
    let mut buf = [0u8; 32];
    buf[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(U256::from_be_bytes::<32>(buf))
}

pub(crate) fn decode_hash32(rlp: &Rlp) -> Result<Hash32, EvmError> {
    let bytes = rlp.data().map_err(|_| EvmError::MalformedRlp)?;
    if bytes.len() != 32 {
        return Err(EvmError::InvalidHashLength);
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(bytes);
    Ok(Hash32::from_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_account() -> EvmAccount {
        EvmAccount {
            nonce: 42,
            balance: U256::from(1_000_000u64),
            storage_root: sango_mpt::empty_root(),
            code_hash: empty_code_hash(),
        }
    }

    #[test]
    fn empty_code_hash_matches_ethereum() {
        let expected = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
        assert_eq!(hex::encode(empty_code_hash().as_bytes()), expected);
    }

    #[test]
    fn account_roundtrip() {
        let acc = sample_account();
        let bytes = encode_account(&acc);
        let decoded = decode_account(&bytes).unwrap();
        assert_eq!(decoded, acc);
    }

    #[test]
    fn zero_account_encodes_with_short_ints() {
        // nonce=0, balance=0 → byte strings vides.
        // storage_root et code_hash sont des hashes 32-byte fixes.
        let acc = EvmAccount {
            nonce: 0,
            balance: U256::ZERO,
            storage_root: sango_mpt::empty_root(),
            code_hash: empty_code_hash(),
        };
        let bytes = encode_account(&acc);
        let decoded = decode_account(&bytes).unwrap();
        assert_eq!(decoded, acc);
    }

    #[test]
    fn nonce_max_u64_roundtrip() {
        let mut acc = sample_account();
        acc.nonce = u64::MAX;
        let bytes = encode_account(&acc);
        assert_eq!(decode_account(&bytes).unwrap(), acc);
    }

    #[test]
    fn balance_max_u256_roundtrip() {
        let mut acc = sample_account();
        acc.balance = U256::MAX;
        let bytes = encode_account(&acc);
        assert_eq!(decode_account(&bytes).unwrap(), acc);
    }

    #[test]
    fn decode_rejects_wrong_item_count() {
        // Liste de 3 items.
        let mut s = RlpStream::new_list(3);
        s.append(&1u64);
        s.append(&2u64);
        s.append(&vec![0u8; 32]);
        let bytes = s.out().to_vec();
        assert_eq!(
            decode_account(&bytes).unwrap_err(),
            EvmError::InvalidAccountRlp
        );
    }

    #[test]
    fn decode_rejects_non_list() {
        let bytes = vec![0x80]; // byte string vide
        assert_eq!(
            decode_account(&bytes).unwrap_err(),
            EvmError::InvalidAccountRlp
        );
    }

    #[test]
    fn decode_rejects_short_hash() {
        let mut s = RlpStream::new_list(4);
        s.append_empty_data(); // nonce 0
        s.append_empty_data(); // balance 0
        s.append(&vec![0u8; 20]); // storage_root trop court
        s.append(&vec![0u8; 32]);
        let bytes = s.out().to_vec();
        assert_eq!(
            decode_account(&bytes).unwrap_err(),
            EvmError::InvalidHashLength
        );
    }

    #[test]
    fn decode_rejects_overflow_u64() {
        let mut s = RlpStream::new_list(4);
        s.append(&vec![0xffu8; 9]); // nonce : 9 bytes > u64
        s.append_empty_data();
        s.append(&vec![0u8; 32]);
        s.append(&vec![0u8; 32]);
        let bytes = s.out().to_vec();
        let err = decode_account(&bytes).unwrap_err();
        assert!(matches!(err, EvmError::IntegerOverflow { .. }));
    }
}
