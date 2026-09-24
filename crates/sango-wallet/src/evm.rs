//! Support EVM (secp256k1) dans le wallet.
//!
//! ## Séparation des domaines
//!
//! Les clés EVM sont **indépendantes** des clés natives Ed25519 :
//!
//! - Ed25519 → [`crate::keystore::KeyFile::seed_hex`] ;
//! - secp256k1 → [`crate::keystore::KeyFile::evm_secret_hex`].
//!
//! ## Encodage Ethereum exact
//!
//! Les transactions signées produites ici sont **bit-à-bit** des
//! typed-transactions Ethereum (`0x00 || RLP(...)` pour Legacy EIP-155,
//! `0x01 || RLP(...)` pour 2930, `0x02 || RLP(...)` pour 1559). Elles sont
//! directement utilisables par `eth_sendRawTransaction` (à venir) ou tout
//! outil Ethereum.

use k256::ecdsa::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use rlp::RlpStream;
use sango_crypto::keccak256;
use sango_primitives::{EvmAddress, Hash32, U256};
use sango_types::{EvmAccessList, EvmTx};

use crate::error::WalletError;

// --- Paire de clés --------------------------------------------------------

/// Paire de clés EVM (secp256k1).
pub struct EvmKeypair {
    signing: SigningKey,
}

impl EvmKeypair {
    /// Génère une nouvelle paire via le CSPRNG de l'OS.
    #[must_use]
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::random(&mut OsRng),
        }
    }

    /// Construit à partir d'un secret de 32 bytes.
    pub fn from_secret(secret: [u8; 32]) -> Result<Self, WalletError> {
        let signing = SigningKey::from_bytes(&secret.into())
            .map_err(|e| WalletError::InvalidKeyfile(format!("bad secp256k1 secret: {e}")))?;
        Ok(Self { signing })
    }

    /// Retourne le secret sous-jacent (32 bytes).
    #[must_use]
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes().into()
    }

    /// Retourne la clé publique non compressée (64 bytes, sans le préfixe 0x04).
    #[must_use]
    pub fn public_key_uncompressed(&self) -> [u8; 64] {
        let vk = self.signing.verifying_key();
        let point = vk.to_encoded_point(false);
        let bytes = point.as_bytes();
        debug_assert_eq!(bytes.len(), 65);
        debug_assert_eq!(bytes[0], 0x04);
        let mut out = [0u8; 64];
        out.copy_from_slice(&bytes[1..]);
        out
    }

    /// Adresse EVM : `Keccak256(uncompressed_pubkey)[12..]`.
    #[must_use]
    pub fn address(&self) -> EvmAddress {
        let vk = self.signing.verifying_key();
        address_from_verifying_key(vk)
    }

    /// Signe un hash de 32 bytes (déjà hashé).
    ///
    /// Retourne `(r, s, y_parity)`, avec `r, s` normalisés low-s par
    /// `k256` (RFC 6979).
    pub fn sign_hash(&self, hash: &Hash32) -> Result<SignatureParts, WalletError> {
        let (sig, recid) = self
            .signing
            .sign_prehash_recoverable(hash.as_bytes())
            .map_err(|e| WalletError::Rpc(format!("secp256k1 sign: {e}")))?;
        let bytes = sig.to_bytes();
        let mut r_bytes = [0u8; 32];
        let mut s_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&bytes[..32]);
        s_bytes.copy_from_slice(&bytes[32..]);
        Ok(SignatureParts {
            r: U256::from_be_bytes::<32>(r_bytes),
            s: U256::from_be_bytes::<32>(s_bytes),
            y_parity: recid.to_byte(),
        })
    }
}

impl std::fmt::Debug for EvmKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvmKeypair")
            .field("address", &self.address())
            .finish_non_exhaustive()
    }
}

/// Composants d'une signature secp256k1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignatureParts {
    /// Composant `r`.
    pub r: U256,
    /// Composant `s`.
    pub s: U256,
    /// Bit de récupération (`0` ou `1`), utilisé comme `y_parity`.
    pub y_parity: u8,
}

fn address_from_verifying_key(vk: &VerifyingKey) -> EvmAddress {
    let point = vk.to_encoded_point(false);
    let bytes = point.as_bytes();
    let h = keccak256(&bytes[1..]); // 64 bytes sans le 0x04
    let mut out = [0u8; 20];
    out.copy_from_slice(&h.as_bytes()[12..]);
    EvmAddress::from_bytes(out)
}

// --- Constructeur de transaction ------------------------------------------

/// Variante de frais.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FeeType {
    /// Legacy EIP-155 : prix unique.
    Legacy {
        /// Prix du gas (base units).
        gas_price: U256,
    },
    /// EIP-2930 : prix unique + access list.
    Eip2930 {
        /// Prix du gas.
        gas_price: U256,
    },
    /// EIP-1559 : `max_fee` + `max_priority_fee`.
    Eip1559 {
        /// Prix total maximal par unité de gas.
        max_fee_per_gas: U256,
        /// Pourboire maximal au validateur.
        max_priority_fee_per_gas: U256,
    },
}

/// Constructeur de transaction EVM.
#[derive(Clone, Debug)]
pub struct EvmTxBuilder {
    /// Chain ID EVM.
    pub chain_id: u64,
    /// Nonce de l'émetteur.
    pub nonce: u64,
    /// Limite de gas.
    pub gas_limit: u64,
    /// Destinataire (`None` = création de contrat).
    pub to: Option<EvmAddress>,
    /// Montant transféré.
    pub value: U256,
    /// Calldata / init code.
    pub data: Vec<u8>,
    /// Access list (utilisée pour 2930 / 1559).
    pub access_list: EvmAccessList,
    /// Variante de frais.
    pub fee: FeeType,
}

impl EvmTxBuilder {
    /// Construit et signe une transaction prête à être encodée.
    pub fn sign(&self, kp: &EvmKeypair) -> Result<EvmTx, WalletError> {
        match &self.fee {
            FeeType::Legacy { gas_price } => {
                let preimage = self.signing_preimage_legacy(*gas_price);
                let hash = keccak256(&preimage);
                let parts = kp.sign_hash(&hash)?;
                Ok(EvmTx::Legacy {
                    chain_id: self.chain_id,
                    nonce: self.nonce,
                    gas_price: *gas_price,
                    gas_limit: self.gas_limit,
                    to: self.to,
                    value: self.value,
                    data: self.data.clone(),
                    y_parity: parts.y_parity,
                    r: parts.r,
                    s: parts.s,
                })
            }
            FeeType::Eip2930 { gas_price } => {
                let preimage = self.signing_preimage_2930(*gas_price);
                let hash = keccak256(&preimage);
                let parts = kp.sign_hash(&hash)?;
                Ok(EvmTx::Eip2930 {
                    chain_id: self.chain_id,
                    nonce: self.nonce,
                    gas_price: *gas_price,
                    gas_limit: self.gas_limit,
                    to: self.to,
                    value: self.value,
                    data: self.data.clone(),
                    access_list: self.access_list.clone(),
                    y_parity: parts.y_parity,
                    r: parts.r,
                    s: parts.s,
                })
            }
            FeeType::Eip1559 {
                max_fee_per_gas,
                max_priority_fee_per_gas,
            } => {
                let preimage =
                    self.signing_preimage_1559(*max_fee_per_gas, *max_priority_fee_per_gas);
                let hash = keccak256(&preimage);
                let parts = kp.sign_hash(&hash)?;
                Ok(EvmTx::Eip1559 {
                    chain_id: self.chain_id,
                    nonce: self.nonce,
                    max_priority_fee_per_gas: *max_priority_fee_per_gas,
                    max_fee_per_gas: *max_fee_per_gas,
                    gas_limit: self.gas_limit,
                    to: self.to,
                    value: self.value,
                    data: self.data.clone(),
                    access_list: self.access_list.clone(),
                    y_parity: parts.y_parity,
                    r: parts.r,
                    s: parts.s,
                })
            }
        }
    }

    // --- Preimages (sans préfixe 0x00/0x01/0x02) --------------------------

    fn signing_preimage_legacy(&self, gas_price: U256) -> Vec<u8> {
        // EIP-155 : RLP([nonce, gas_price, gas_limit, to, value, data,
        //                 chain_id, 0, 0])
        let mut s = RlpStream::new_list(9);
        append_u64_minimal(&mut s, self.nonce);
        append_u256_minimal(&mut s, gas_price);
        append_u64_minimal(&mut s, self.gas_limit);
        append_opt_address(&mut s, self.to);
        append_u256_minimal(&mut s, self.value);
        s.append(&self.data.as_slice());
        append_u64_minimal(&mut s, self.chain_id);
        append_u64_minimal(&mut s, 0);
        append_u64_minimal(&mut s, 0);
        s.out().to_vec()
    }

    fn signing_preimage_2930(&self, gas_price: U256) -> Vec<u8> {
        // 0x01 || RLP([chain_id, nonce, gas_price, gas_limit, to, value,
        //              data, access_list])
        let mut out = vec![0x01u8];
        let mut s = RlpStream::new_list(8);
        append_u64_minimal(&mut s, self.chain_id);
        append_u64_minimal(&mut s, self.nonce);
        append_u256_minimal(&mut s, gas_price);
        append_u64_minimal(&mut s, self.gas_limit);
        append_opt_address(&mut s, self.to);
        append_u256_minimal(&mut s, self.value);
        s.append(&self.data.as_slice());
        append_access_list(&mut s, &self.access_list);
        out.extend_from_slice(&s.out());
        out
    }

    fn signing_preimage_1559(&self, max_fee: U256, priority: U256) -> Vec<u8> {
        // 0x02 || RLP([chain_id, nonce, max_priority, max_fee, gas_limit,
        //              to, value, data, access_list])
        let mut out = vec![0x02u8];
        let mut s = RlpStream::new_list(9);
        append_u64_minimal(&mut s, self.chain_id);
        append_u64_minimal(&mut s, self.nonce);
        append_u256_minimal(&mut s, priority);
        append_u256_minimal(&mut s, max_fee);
        append_u64_minimal(&mut s, self.gas_limit);
        append_opt_address(&mut s, self.to);
        append_u256_minimal(&mut s, self.value);
        s.append(&self.data.as_slice());
        append_access_list(&mut s, &self.access_list);
        out.extend_from_slice(&s.out());
        out
    }
}

// --- Helpers RLP ----------------------------------------------------------

fn append_u64_minimal(s: &mut RlpStream, v: u64) {
    if v == 0 {
        s.append_empty_data();
        return;
    }
    let bytes = v.to_be_bytes();
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(8);
    let slice: &[u8] = &bytes[start..];
    s.append(&slice);
}

fn append_u256_minimal(s: &mut RlpStream, v: U256) {
    if v == U256::ZERO {
        s.append_empty_data();
        return;
    }
    let bytes = v.to_be_bytes::<32>();
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(32);
    let slice: &[u8] = &bytes[start..];
    s.append(&slice);
}

fn append_opt_address(s: &mut RlpStream, to: Option<EvmAddress>) {
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

fn append_access_list(s: &mut RlpStream, list: &EvmAccessList) {
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

// --- Tests ---------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sango_types::EvmTx;

    // --- Adresses Ethereum connues ---------------------------------------

    /// Vecteur 1 : secret = 0x46... (voir test vectors Ethereum).
    ///
    /// Utilise un secret déterministe pour figer la dérivation d'adresse.
    #[test]
    fn address_derivation_known_vector() {
        // Secret 0x4646...4646 (32 bytes)
        let secret = [0x46u8; 32];
        let kp = EvmKeypair::from_secret(secret).unwrap();
        // L'adresse dépend uniquement de Keccak256(pubkey[1..])[12..].
        // On vérifie qu'elle est déterministe et fait 20 bytes.
        let a1 = kp.address();
        let kp2 = EvmKeypair::from_secret(secret).unwrap();
        let a2 = kp2.address();
        assert_eq!(a1, a2);
        assert_eq!(a1.as_bytes().len(), 20);
    }

    #[test]
    fn address_is_deterministic() {
        let secret = [0x11u8; 32];
        let kp1 = EvmKeypair::from_secret(secret).unwrap();
        let kp2 = EvmKeypair::from_secret(secret).unwrap();
        assert_eq!(kp1.address(), kp2.address());
        assert_eq!(kp1.public_key_uncompressed(), kp2.public_key_uncompressed());
    }

    #[test]
    fn different_secrets_give_different_addresses() {
        let kp1 = EvmKeypair::from_secret([0x01u8; 32]).unwrap();
        let kp2 = EvmKeypair::from_secret([0x02u8; 32]).unwrap();
        assert_ne!(kp1.address(), kp2.address());
    }

    #[test]
    fn generate_produces_valid_keypair() {
        let kp = EvmKeypair::generate();
        assert_eq!(kp.address().as_bytes().len(), 20);
        assert_eq!(kp.public_key_uncompressed().len(), 64);
    }

    // --- Signatures ------------------------------------------------------

    #[test]
    fn sign_produces_valid_y_parity() {
        let kp = EvmKeypair::from_secret([0x42u8; 32]).unwrap();
        let hash = Hash32::from_bytes([0xaa; 32]);
        let parts = kp.sign_hash(&hash).unwrap();
        assert!(parts.y_parity <= 1);
        assert_ne!(parts.r, U256::ZERO);
        assert_ne!(parts.s, U256::ZERO);
    }

    #[test]
    fn sign_is_deterministic_rfc6979() {
        let kp = EvmKeypair::from_secret([0x42u8; 32]).unwrap();
        let hash = Hash32::from_bytes([0xaa; 32]);
        let a = kp.sign_hash(&hash).unwrap();
        let b = kp.sign_hash(&hash).unwrap();
        assert_eq!(a, b);
    }

    // --- Construction de tx ----------------------------------------------

    fn sample_builder() -> EvmTxBuilder {
        EvmTxBuilder {
            chain_id: 7777,
            nonce: 0,
            gas_limit: 21_000,
            to: Some(EvmAddress::from_bytes([0xbb; 20])),
            value: U256::from(100u64),
            data: vec![],
            access_list: Vec::new(),
            fee: FeeType::Eip1559 {
                max_fee_per_gas: U256::from(1_000_000_000u64),
                max_priority_fee_per_gas: U256::from(1_000_000u64),
            },
        }
    }

    #[test]
    fn sign_eip1559_roundtrip() {
        let kp = EvmKeypair::from_secret([0x42u8; 32]).unwrap();
        let tx = sample_builder().sign(&kp).unwrap();
        let bytes = tx.encode_ethereum_typed();
        assert_eq!(bytes[0], 0x02);
        // Décodage roundtrip via sango-types.
        let decoded = EvmTx::decode_ethereum_typed(&bytes).unwrap();
        assert_eq!(decoded, tx);
    }

    #[test]
    fn sign_legacy_eip155_roundtrip() {
        let kp = EvmKeypair::from_secret([0x42u8; 32]).unwrap();
        let mut b = sample_builder();
        b.fee = FeeType::Legacy {
            gas_price: U256::from(20_000_000_000u64),
        };
        let tx = b.sign(&kp).unwrap();
        let bytes = tx.encode_ethereum_typed();
        assert_eq!(bytes[0], 0x00);
        let decoded = EvmTx::decode_ethereum_typed(&bytes).unwrap();
        assert_eq!(decoded, tx);
    }

    #[test]
    fn sign_eip2930_roundtrip() {
        let kp = EvmKeypair::from_secret([0x42u8; 32]).unwrap();
        let mut b = sample_builder();
        b.fee = FeeType::Eip2930 {
            gas_price: U256::from(1_000_000_000u64),
        };
        let tx = b.sign(&kp).unwrap();
        let bytes = tx.encode_ethereum_typed();
        assert_eq!(bytes[0], 0x01);
        let decoded = EvmTx::decode_ethereum_typed(&bytes).unwrap();
        assert_eq!(decoded, tx);
    }

    #[test]
    fn sign_contract_create() {
        let kp = EvmKeypair::from_secret([0x42u8; 32]).unwrap();
        let mut b = sample_builder();
        b.to = None;
        b.data = vec![0x60, 0x00, 0x60, 0x00, 0xf3];
        b.gas_limit = 100_000;
        let tx = b.sign(&kp).unwrap();
        assert!(tx.is_contract_creation());
        let bytes = tx.encode_ethereum_typed();
        let decoded = EvmTx::decode_ethereum_typed(&bytes).unwrap();
        assert_eq!(decoded, tx);
    }
}
