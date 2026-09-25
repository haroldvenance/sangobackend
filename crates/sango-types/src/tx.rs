//! Enveloppe de transaction unifiée Sango V1.
//!
//! [`Tx`] est l'enveloppe de **transport et d'exécution** qui vit dans un
//! [`crate::Block`]. Elle n'a **pas** vocation à remplacer
//! [`crate::Transaction`] (transaction native Ed25519) ni [`crate::EvmTx`]
//! (transaction EVM secp256k1) : elle les enveloppe.
//!
//! ## Discriminant Sango
//!
//! ```text
//! 0x01 → Tx::Native(Transaction)
//! 0x02 → Tx::Evm(EvmTx)
//! ```
//!
//! Ce discriminant est **indépendant** des types Ethereum typés
//! (`0x00` Legacy, `0x01` EIP-2930, `0x02` EIP-1559, `0x04` EIP-7702). Un
//! `Tx::Evm(EvmTx::Eip1559 { .. })` contient donc un discriminant Sango
//! `0x02` **et** un typed-tx Ethereum `0x02` — coïncidence numérique sans
//! ambiguïté (les deux vivent à des niveaux différents).
//!
//! ## Bytes canoniques vs encodage Sango
//!
//! - [`Tx::canonical_bytes`] retourne les bytes utilisés **comme valeur
//!   MPT** dans `transaction_root`. C'est la forme qui doit matcher
//!   bit-à-bit un client Ethereum (pour les txs EVM).
//! - [`Tx::encode`] (via `sango-codec`) produit une forme
//!   **auto-délimitante** avec discriminant Sango + longueur préfixée
//!   pour l'EVM. Cette forme est utilisée pour la sérialisation `Block`
//!   sur le réseau et sur disque.
//!
//! Les deux ne sont **pas** identiques et ne doivent **pas** être
//! confondues.

use sango_codec::{CodecError, Decode, Decoder, Encode, Encoder};
use sango_crypto::keccak256;
use sango_primitives::Hash32;

use crate::evm::EvmTx;
use crate::transaction::Transaction;

/// Discriminant Sango : transaction native.
pub const TX_DISCRIMINANT_NATIVE: u8 = 0x01;

/// Discriminant Sango : transaction EVM.
pub const TX_DISCRIMINANT_EVM: u8 = 0x02;

/// Enveloppe de transaction Sango V1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Tx {
    /// Transaction native Sango (Ed25519, `TxKind` de staking, etc.).
    Native(Transaction),
    /// Transaction EVM Ethereum-compatible (secp256k1, typed).
    Evm(EvmTx),
}

impl Tx {
    /// Discriminant Sango de l'enveloppe.
    #[must_use]
    pub const fn discriminant(&self) -> u8 {
        match self {
            Tx::Native(_) => TX_DISCRIMINANT_NATIVE,
            Tx::Evm(_) => TX_DISCRIMINANT_EVM,
        }
    }

    /// Bytes canoniques utilisés comme **valeur MPT** dans
    /// `transaction_root`.
    ///
    /// - `Tx::Native(tx)` : `tx.encode_to_vec()` (Sango natif).
    /// - `Tx::Evm(tx)` : `tx.encode_ethereum_typed()` (bit-à-bit
    ///   Ethereum).
    ///
    /// **Important** : ne **pas** préfixer ces bytes par RLP — la valeur
    /// MPT est directement le résultat de cette méthode.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        match self {
            Tx::Native(tx) => tx.encode_to_vec(),
            Tx::Evm(tx) => tx.encode_ethereum_typed(),
        }
    }

    /// Hash canonique de la transaction.
    ///
    /// - Native : `Keccak256("SANGO/TX/V1" || unsigned)` — voir
    ///   [`Transaction::hash`].
    /// - EVM : `Keccak256(typed_tx_bytes)` — sémantique Ethereum exacte
    ///   (le hash de tx EVM **est** le hash du typed-tx).
    #[must_use]
    pub fn hash(&self) -> Hash32 {
        match self {
            Tx::Native(tx) => tx.hash(),
            Tx::Evm(tx) => keccak256(&tx.encode_ethereum_typed()),
        }
    }

    /// Vrai si c'est une transaction native.
    #[must_use]
    pub const fn is_native(&self) -> bool {
        matches!(self, Tx::Native(_))
    }

    /// Vrai si c'est une transaction EVM.
    #[must_use]
    pub const fn is_evm(&self) -> bool {
        matches!(self, Tx::Evm(_))
    }
}

impl From<Transaction> for Tx {
    fn from(tx: Transaction) -> Self {
        Tx::Native(tx)
    }
}

impl From<EvmTx> for Tx {
    fn from(tx: EvmTx) -> Self {
        Tx::Evm(tx)
    }
}

impl Encode for Tx {
    fn encode(&self, enc: &mut Encoder) {
        enc.write_u8(self.discriminant());
        match self {
            Tx::Native(tx) => tx.encode(enc),
            Tx::Evm(tx) => {
                // Longueur préfixée pour délimiter le typed-tx Ethereum
                // sans dépendre du parsing RLP côté décodeur.
                let bytes = tx.encode_ethereum_typed();
                enc.write_bytes(&bytes);
            }
        }
    }
}

impl Decode for Tx {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let tag = dec.read_u8()?;
        match tag {
            TX_DISCRIMINANT_NATIVE => Ok(Tx::Native(Transaction::decode(dec)?)),
            TX_DISCRIMINANT_EVM => {
                let bytes = dec.read_bytes()?;
                let tx = EvmTx::decode_ethereum_typed(&bytes).map_err(|_| {
                    CodecError::MalformedPayload {
                        reason: "invalid EVM typed transaction payload",
                    }
                })?;
                Ok(Tx::Evm(tx))
            }
            other => Err(CodecError::InvalidTag { tag: other }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm::{EvmAccessListItem, EvmAuthorization};
    use crate::transaction::TxKind;
    use sango_primitives::{Amount, ChainId32, EvmAddress, NativeAddress, Signature, U256};

    fn native_tx(nonce: u64) -> Transaction {
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

    fn addr(b: u8) -> EvmAddress {
        EvmAddress::from_bytes([b; 20])
    }

    fn u(v: u64) -> U256 {
        U256::from(v)
    }

    fn h(b: u8) -> Hash32 {
        Hash32::from_bytes([b; 32])
    }

    fn evm_legacy() -> EvmTx {
        EvmTx::Legacy {
            chain_id: 7777,
            nonce: 0,
            gas_price: u(1_000_000_000),
            gas_limit: 21_000,
            to: Some(addr(0xaa)),
            value: u(100),
            data: vec![0xde, 0xad],
            y_parity: 0,
            r: U256::from(7u64),
            s: U256::from(11u64),
        }
    }

    fn evm_eip2930() -> EvmTx {
        EvmTx::Eip2930 {
            chain_id: 7777,
            nonce: 1,
            gas_price: u(1_000_000_000),
            gas_limit: 50_000,
            to: Some(addr(0x11)),
            value: u(0),
            data: vec![],
            access_list: vec![EvmAccessListItem {
                address: addr(0x22),
                storage_keys: vec![h(0x01)],
            }],
            y_parity: 1,
            r: U256::from(3u64),
            s: U256::from(4u64),
        }
    }

    fn evm_eip1559() -> EvmTx {
        EvmTx::Eip1559 {
            chain_id: 7777,
            nonce: 5,
            max_priority_fee_per_gas: u(1_000_000),
            max_fee_per_gas: u(50_000_000_000),
            gas_limit: 21_000,
            to: Some(addr(0xcc)),
            value: u(12_345),
            data: vec![],
            access_list: vec![],
            y_parity: 0,
            r: U256::from(99u64),
            s: U256::from(77u64),
        }
    }

    fn evm_eip7702() -> EvmTx {
        EvmTx::Eip7702 {
            chain_id: 7777,
            nonce: 3,
            max_priority_fee_per_gas: u(1),
            max_fee_per_gas: u(200),
            gas_limit: 500_000,
            to: addr(0xee),
            value: u(0),
            data: vec![0xaa, 0xbb],
            access_list: vec![],
            authorization_list: vec![EvmAuthorization {
                chain_id: u(7777),
                address: addr(0xef),
                nonce: 0,
                y_parity: 1,
                r: U256::from(11u64),
                s: U256::from(22u64),
            }],
            y_parity: 0,
            r: U256::from(33u64),
            s: U256::from(44u64),
        }
    }

    // --- Roundtrip par variant ---------------------------------------------

    #[test]
    fn native_roundtrip() {
        let tx = Tx::Native(native_tx(7));
        let bytes = tx.encode_to_vec();
        assert_eq!(Tx::decode_exact(&bytes).unwrap(), tx);
    }

    #[test]
    fn evm_legacy_roundtrip() {
        let tx = Tx::Evm(evm_legacy());
        let bytes = tx.encode_to_vec();
        assert_eq!(Tx::decode_exact(&bytes).unwrap(), tx);
    }

    #[test]
    fn evm_eip2930_roundtrip() {
        let tx = Tx::Evm(evm_eip2930());
        let bytes = tx.encode_to_vec();
        assert_eq!(Tx::decode_exact(&bytes).unwrap(), tx);
    }

    #[test]
    fn evm_eip1559_roundtrip() {
        let tx = Tx::Evm(evm_eip1559());
        let bytes = tx.encode_to_vec();
        assert_eq!(Tx::decode_exact(&bytes).unwrap(), tx);
    }

    #[test]
    fn evm_eip7702_roundtrip() {
        let tx = Tx::Evm(evm_eip7702());
        let bytes = tx.encode_to_vec();
        assert_eq!(Tx::decode_exact(&bytes).unwrap(), tx);
    }

    // --- Discriminant ------------------------------------------------------

    #[test]
    fn discriminant_is_stable() {
        assert_eq!(Tx::Native(native_tx(0)).discriminant(), 0x01);
        assert_eq!(Tx::Evm(evm_legacy()).discriminant(), 0x02);
        assert_eq!(Tx::Evm(evm_eip1559()).discriminant(), 0x02);
    }

    #[test]
    fn discriminant_prefix_in_codec() {
        let bytes = Tx::Native(native_tx(0)).encode_to_vec();
        assert_eq!(bytes[0], 0x01);
        let bytes = Tx::Evm(evm_legacy()).encode_to_vec();
        assert_eq!(bytes[0], 0x02);
    }

    // --- Rejets ------------------------------------------------------------

    #[test]
    fn unknown_discriminant_rejected() {
        let err = Tx::decode_exact(&[0x05]).unwrap_err();
        assert!(matches!(err, CodecError::InvalidTag { tag: 0x05 }));
    }

    #[test]
    fn zero_discriminant_rejected() {
        let err = Tx::decode_exact(&[0x00]).unwrap_err();
        assert!(matches!(err, CodecError::InvalidTag { tag: 0x00 }));
    }

    #[test]
    fn truncated_native_rejected() {
        let tx = Tx::Native(native_tx(1));
        let bytes = tx.encode_to_vec();
        let truncated = &bytes[..bytes.len() - 1];
        assert!(Tx::decode_exact(truncated).is_err());
    }

    #[test]
    fn truncated_evm_rejected() {
        let tx = Tx::Evm(evm_legacy());
        let bytes = tx.encode_to_vec();
        let truncated = &bytes[..bytes.len() - 1];
        assert!(Tx::decode_exact(truncated).is_err());
    }

    #[test]
    fn malformed_evm_payload_rejected() {
        // Discriminant 0x02 + longueur 2 + bytes invalides pour EvmTx.
        let mut bytes = vec![0x02u8];
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&[0xff, 0xfe]);
        let err = Tx::decode_exact(&bytes).unwrap_err();
        assert!(matches!(err, CodecError::MalformedPayload { .. }));
    }

    #[test]
    fn trailing_bytes_rejected() {
        let tx = Tx::Native(native_tx(0));
        let mut bytes = tx.encode_to_vec();
        bytes.push(0x00);
        assert!(Tx::decode_exact(&bytes).is_err());
    }

    // --- canonical_bytes vs encode -----------------------------------------

    #[test]
    fn native_canonical_bytes_equals_sango_codec() {
        let inner = native_tx(3);
        let wrapped = Tx::Native(inner.clone());
        assert_eq!(wrapped.canonical_bytes(), inner.encode_to_vec());
    }

    #[test]
    fn evm_canonical_bytes_equals_ethereum_typed() {
        for inner in [evm_legacy(), evm_eip2930(), evm_eip1559(), evm_eip7702()] {
            let expected = inner.encode_ethereum_typed();
            let wrapped = Tx::Evm(inner);
            assert_eq!(wrapped.canonical_bytes(), expected);
        }
    }

    #[test]
    fn evm_legacy_canonical_bytes_start_with_eth_type_zero() {
        // Pour Legacy, canonical_bytes[0] == 0x00 (Ethereum), PAS 0x02
        // (discriminant Sango). C'est le point crucial : aucun préfixe
        // Sango ne doit fuiter dans les bytes MPT.
        let wrapped = Tx::Evm(evm_legacy());
        let bytes = wrapped.canonical_bytes();
        assert_eq!(bytes[0], 0x00);
        // Le codec Sango, lui, commence bien par 0x02.
        let codec_bytes = wrapped.encode_to_vec();
        assert_eq!(codec_bytes[0], 0x02);
    }

    #[test]
    fn evm_eip1559_sango_discriminant_equals_eth_type_by_coincidence() {
        // Coïncidence numérique documentée : discriminant Sango EVM = 0x02
        // et type Ethereum EIP-1559 = 0x02. Les deux vivent à des niveaux
        // différents (enveloppe vs typed-tx).
        let wrapped = Tx::Evm(evm_eip1559());
        assert_eq!(wrapped.discriminant(), 0x02);
        assert_eq!(wrapped.canonical_bytes()[0], 0x02);
    }

    // --- hash ---------------------------------------------------------------

    #[test]
    fn native_hash_matches_inner() {
        let inner = native_tx(2);
        let wrapped = Tx::Native(inner.clone());
        assert_eq!(wrapped.hash(), inner.hash());
    }

    #[test]
    fn evm_hash_is_keccak_of_typed_bytes() {
        let inner = evm_eip1559();
        let expected = keccak256(&inner.encode_ethereum_typed());
        let wrapped = Tx::Evm(inner);
        assert_eq!(wrapped.hash(), expected);
    }

    // --- Accesseurs ---------------------------------------------------------

    #[test]
    fn is_native_is_evm() {
        assert!(Tx::Native(native_tx(0)).is_native());
        assert!(!Tx::Native(native_tx(0)).is_evm());
        assert!(Tx::Evm(evm_legacy()).is_evm());
        assert!(!Tx::Evm(evm_legacy()).is_native());
    }

    // --- From ---------------------------------------------------------------

    #[test]
    fn from_native() {
        let t = native_tx(0);
        let wrapped: Tx = t.clone().into();
        assert_eq!(wrapped, Tx::Native(t));
    }

    #[test]
    fn from_evm() {
        let t = evm_legacy();
        let wrapped: Tx = t.clone().into();
        assert_eq!(wrapped, Tx::Evm(t));
    }
}
