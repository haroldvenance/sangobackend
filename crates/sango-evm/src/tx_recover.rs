//! Recovery cryptographique du sender d'une transaction EVM.
//!
//! ## Règle normative
//!
//! ```text
//! signing_payload(tx)  →  message
//! Keccak256(message)   →  prehash (32 bytes)
//! secp256k1 recovery (r, s, y_parity)
//!     →  uncompressed public key (65 bytes : 0x04 || X || Y)
//! Keccak256(pubkey[1..])[12..]
//!     →  EvmAddress
//! ```
//!
//! Aucune confiance n'est accordée à un sender fourni par l'appelant :
//! il est **toujours** dérivé de la signature.
//!
//! ## TODO 4c.x
//!
//! La même logique existe dans `sango-mempool::evm_pool::recover_sender`.
//! À dédupliquer dans une étape ultérieure (migration vers ce module).
//! Ici, on la duplique pour ne pas refactorer le mempool dans 4c.3.3.

use rlp::RlpStream;
use sango_crypto::keccak256;
use sango_primitives::{EvmAddress, U256};
use sango_types::{EvmAccessList, EvmAuthorization, EvmTx};

use crate::error::EvmError;

/// Récupère l'adresse EVM de l'émetteur d'une tx depuis sa signature.
pub fn recover_sender(tx: &EvmTx) -> Result<EvmAddress, EvmError> {
    let payload = signing_payload(tx);
    let prehash = keccak256(&payload);

    let (r, s, y_parity) = match tx {
        EvmTx::Legacy { r, s, y_parity, .. }
        | EvmTx::Eip2930 { r, s, y_parity, .. }
        | EvmTx::Eip1559 { r, s, y_parity, .. }
        | EvmTx::Eip7702 { r, s, y_parity, .. } => (*r, *s, *y_parity),
    };

    if y_parity > 1 {
        return Err(EvmError::InvalidSignature);
    }

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&r.to_be_bytes::<32>());
    sig_bytes[32..].copy_from_slice(&s.to_be_bytes::<32>());

    let signature = k256::ecdsa::Signature::from_slice(&sig_bytes)
        .map_err(|_| EvmError::InvalidSignature)?;

    let recovery_id = k256::ecdsa::RecoveryId::try_from(y_parity)
        .map_err(|_| EvmError::InvalidSignature)?;

    let verifying_key =
        k256::ecdsa::VerifyingKey::recover_from_prehash(prehash.as_bytes(), &signature, recovery_id)
            .map_err(|_| EvmError::InvalidSignature)?;

    let point = verifying_key.to_encoded_point(false);
    let encoded = point.as_bytes();
    if encoded.len() != 65 || encoded[0] != 0x04 {
        return Err(EvmError::InvalidSignature);
    }
    let addr_hash = keccak256(&encoded[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&addr_hash.as_bytes()[12..]);
    Ok(EvmAddress::from_bytes(addr))
}

/// `max_fee_per_gas` brut d'une tx.
#[must_use]
pub fn max_fee_per_gas(tx: &EvmTx) -> U256 {
    match tx {
        EvmTx::Legacy { gas_price, .. } | EvmTx::Eip2930 { gas_price, .. } => *gas_price,
        EvmTx::Eip1559 { max_fee_per_gas, .. } | EvmTx::Eip7702 { max_fee_per_gas, .. } => {
            *max_fee_per_gas
        }
    }
}

/// `max_priority_fee_per_gas` brut d'une tx.
#[must_use]
pub fn max_priority_fee(tx: &EvmTx) -> U256 {
    match tx {
        EvmTx::Legacy { gas_price, .. } | EvmTx::Eip2930 { gas_price, .. } => *gas_price,
        EvmTx::Eip1559 {
            max_priority_fee_per_gas,
            ..
        }
        | EvmTx::Eip7702 {
            max_priority_fee_per_gas,
            ..
        } => *max_priority_fee_per_gas,
    }
}

/// Priorité effective d'une tx pour un `base_fee` donné.
///
/// ```text
/// eff_priority = min(max_priority_fee, max_fee - base_fee)
/// ```
#[must_use]
pub fn effective_priority_fee(tx: &EvmTx, base_fee: U256) -> U256 {
    let max_fee = max_fee_per_gas(tx);
    let max_priority = max_priority_fee(tx);
    let budget = max_fee.saturating_sub(base_fee);
    max_priority.min(budget)
}

// --- Signing payload -------------------------------------------------------

fn signing_payload(tx: &EvmTx) -> Vec<u8> {
    match tx {
        EvmTx::Legacy {
            chain_id,
            nonce,
            gas_price,
            gas_limit,
            to,
            value,
            data,
            ..
        } => {
            let mut s = RlpStream::new_list(9);
            enc_u64(&mut s, *nonce);
            enc_u256(&mut s, *gas_price);
            enc_u64(&mut s, *gas_limit);
            enc_to(&mut s, *to);
            enc_u256(&mut s, *value);
            s.append(&data.as_slice());
            enc_u64(&mut s, *chain_id);
            s.append_empty_data();
            s.append_empty_data();
            s.out().to_vec()
        }
        EvmTx::Eip2930 {
            chain_id,
            nonce,
            gas_price,
            gas_limit,
            to,
            value,
            data,
            access_list,
            ..
        } => {
            let mut s = RlpStream::new_list(11);
            enc_u64(&mut s, *chain_id);
            enc_u64(&mut s, *nonce);
            enc_u256(&mut s, *gas_price);
            enc_u64(&mut s, *gas_limit);
            enc_to(&mut s, *to);
            enc_u256(&mut s, *value);
            s.append(&data.as_slice());
            enc_access_list(&mut s, access_list);
            let mut out = vec![0x01u8];
            out.extend_from_slice(&s.out());
            out
        }
        EvmTx::Eip1559 {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            value,
            data,
            access_list,
            ..
        } => {
            let mut s = RlpStream::new_list(12);
            enc_u64(&mut s, *chain_id);
            enc_u64(&mut s, *nonce);
            enc_u256(&mut s, *max_priority_fee_per_gas);
            enc_u256(&mut s, *max_fee_per_gas);
            enc_u64(&mut s, *gas_limit);
            enc_to(&mut s, *to);
            enc_u256(&mut s, *value);
            s.append(&data.as_slice());
            enc_access_list(&mut s, access_list);
            let mut out = vec![0x02u8];
            out.extend_from_slice(&s.out());
            out
        }
        EvmTx::Eip7702 {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            value,
            data,
            access_list,
            authorization_list,
            ..
        } => {
            let mut s = RlpStream::new_list(13);
            enc_u64(&mut s, *chain_id);
            enc_u64(&mut s, *nonce);
            enc_u256(&mut s, *max_priority_fee_per_gas);
            enc_u256(&mut s, *max_fee_per_gas);
            enc_u64(&mut s, *gas_limit);
            let to_bytes: &[u8] = to.as_bytes();
            s.append(&to_bytes);
            enc_u256(&mut s, *value);
            s.append(&data.as_slice());
            enc_access_list(&mut s, access_list);
            enc_authorization_list(&mut s, authorization_list);
            let mut out = vec![0x04u8];
            out.extend_from_slice(&s.out());
            out
        }
    }
}

fn enc_u64(s: &mut RlpStream, v: u64) {
    let bytes = v.to_be_bytes();
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(8);
    let slice: &[u8] = &bytes[start..];
    s.append(&slice);
}

fn enc_u256(s: &mut RlpStream, v: U256) {
    let bytes = v.to_be_bytes::<32>();
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(32);
    let slice: &[u8] = &bytes[start..];
    s.append(&slice);
}

fn enc_to(s: &mut RlpStream, to: Option<EvmAddress>) {
    match to {
        Some(a) => {
            let bytes: &[u8] = a.as_bytes();
            s.append(&bytes);
        }
        None => {
            s.append_empty_data();
        }
    }
}

fn enc_access_list(s: &mut RlpStream, list: &EvmAccessList) {
    s.begin_list(list.len());
    for item in list {
        s.begin_list(2);
        let addr_bytes: &[u8] = item.address.as_bytes();
        s.append(&addr_bytes);
        s.begin_list(item.storage_keys.len());
        for key in &item.storage_keys {
            let key_bytes: &[u8] = key.as_bytes();
            s.append(&key_bytes);
        }
    }
}

fn enc_authorization_list(s: &mut RlpStream, list: &[EvmAuthorization]) {
    s.begin_list(list.len());
    for auth in list {
        s.begin_list(6);
        enc_u256(s, auth.chain_id);
        let addr_bytes: &[u8] = auth.address.as_bytes();
        s.append(&addr_bytes);
        enc_u64(s, auth.nonce);
        enc_u64(s, auth.y_parity as u64);
        enc_u256(s, auth.r);
        enc_u256(s, auth.s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> EvmAddress {
        EvmAddress::from_bytes([b; 20])
    }

    fn u(v: u64) -> U256 {
        U256::from(v)
    }

    fn signing_key(seed: [u8; 32]) -> k256::ecdsa::SigningKey {
        k256::ecdsa::SigningKey::from_bytes((&seed).into()).expect("valid scalar")
    }

    fn signed_legacy(sk: &k256::ecdsa::SigningKey, nonce: u64, gas_price: u64) -> EvmTx {
        let unsigned = EvmTx::Legacy {
            chain_id: 7777,
            nonce,
            gas_price: u(gas_price),
            gas_limit: 21_000,
            to: Some(addr(0xbb)),
            value: u(100),
            data: vec![],
            y_parity: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };
        let payload = signing_payload(&unsigned);
        let prehash = keccak256(&payload);
        let (sig, recid) = sk.sign_prehash_recoverable(prehash.as_bytes()).expect("sign");
        let sig_bytes = sig.to_bytes();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig_bytes[..32]);
        s.copy_from_slice(&sig_bytes[32..]);
        EvmTx::Legacy {
            chain_id: 7777,
            nonce,
            gas_price: u(gas_price),
            gas_limit: 21_000,
            to: Some(addr(0xbb)),
            value: u(100),
            data: vec![],
            y_parity: recid.to_byte(),
            r: U256::from_be_bytes::<32>(r),
            s: U256::from_be_bytes::<32>(s),
        }
    }

    #[test]
    fn recover_sender_roundtrip() {
        let sk = signing_key([0x42u8; 32]);
        let tx = signed_legacy(&sk, 0, 1_000_000_000);
        let got = recover_sender(&tx).unwrap();

        let vk = sk.verifying_key();
        let point = vk.to_encoded_point(false);
        let h = keccak256(&point.as_bytes()[1..]);
        let mut a = [0u8; 20];
        a.copy_from_slice(&h.as_bytes()[12..]);
        assert_eq!(got, EvmAddress::from_bytes(a));
    }

    #[test]
    fn recover_sender_rejects_bad_y_parity() {
        let sk = signing_key([0x42u8; 32]);
        let tx = signed_legacy(&sk, 0, 1);
        let bad = match tx {
            EvmTx::Legacy { .. } => {
                let mut t = signed_legacy(&sk, 0, 1);
                if let EvmTx::Legacy { y_parity, .. } = &mut t {
                    *y_parity = 2;
                }
                t
            }
            _ => unreachable!(),
        };
        assert_eq!(recover_sender(&bad), Err(EvmError::InvalidSignature));
    }

    #[test]
    fn effective_priority_legacy() {
        let tx = EvmTx::Legacy {
            chain_id: 1,
            nonce: 0,
            gas_price: u(100),
            gas_limit: 21_000,
            to: Some(addr(0xaa)),
            value: u(0),
            data: vec![],
            y_parity: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };
        assert_eq!(effective_priority_fee(&tx, u(30)), u(70));
    }
}
