//! Transaction native Sango V1.

use sango_codec::{CodecError, Decode, Decoder, Encode, Encoder};
use sango_crypto::{domain, keccak256, sign_native, verify_native, CryptoError, NativeKeypair};
use sango_primitives::{Amount, ChainId32, Hash32, NativeAddress, PublicKey, Signature};

/// Type de transaction native.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TxKind {
    /// Transfert de SANGO entre deux comptes natifs.
    Transfer,
    /// Appel d'un contrat EVM.
    ContractCall,
    /// Création d'un contrat EVM.
    ContractCreate,
}

impl TxKind {
    /// Tag canonique (`u8`).
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            TxKind::Transfer => 0x01,
            TxKind::ContractCall => 0x02,
            TxKind::ContractCreate => 0x03,
        }
    }

    /// Parse un tag canonique.
    pub fn from_tag(tag: u8) -> Result<Self, CodecError> {
        match tag {
            0x01 => Ok(TxKind::Transfer),
            0x02 => Ok(TxKind::ContractCall),
            0x03 => Ok(TxKind::ContractCreate),
            other => Err(CodecError::InvalidTag { tag: other }),
        }
    }
}

/// Transaction native Sango V1 (Freeze, section 21).
///
/// ## Ordre canonique
///
/// ```text
/// version || chain_id || nonce || sender || public_key?
/// || gas_limit || max_fee || priority_fee || value
/// || tx_kind || recipient || data || signature
/// ```
///
/// Le `recipient` vaut `None` (NIL) uniquement pour `TxKind::ContractCreate`.
///
/// Le champ `public_key` est **inclus dans les bytes signés** et dans le
/// hash de transaction : impossible pour un attaquant d'ajouter ou
/// retirer la clé après signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transaction {
    /// Version du format de transaction.
    pub version: u32,
    /// Chain ID natif.
    pub chain_id: ChainId32,
    /// Nonce du compte émetteur.
    pub nonce: u64,
    /// Adresse native de l'émetteur.
    pub sender: NativeAddress,
    /// Clé publique Ed25519, si déclarée dans la transaction.
    ///
    /// - `Some(pk)` : **déclaration de clé**. Le réseau vérifie
    ///   `derive_native_address(pk) == sender`. Utilisé pour activer un
    ///   compte fraîchement crédité (ghost) qui n'a pas encore de clé
    ///   enregistrée.
    /// - `None` : le compte doit déjà avoir une clé enregistrée.
    pub public_key: Option<PublicKey>,
    /// Limite de gas.
    pub gas_limit: u64,
    /// Prix maximum par unité de gas (base + priorité).
    pub max_fee: u128,
    /// Pourboire par unité de gas.
    pub priority_fee: u128,
    /// Montant transféré (en base units).
    pub value: Amount,
    /// Type de transaction.
    pub tx_kind: TxKind,
    /// Destinataire. `None` pour `TxKind::ContractCreate`.
    pub recipient: Option<NativeAddress>,
    /// Données d'appel ou bytecode d'initialisation.
    pub data: Vec<u8>,
    /// Signature Ed25519 sur `DOMAIN_TX_V1 || champs hors signature`.
    pub signature: Signature,
}

impl Transaction {
    /// Vrai si la transaction déclare une clé publique (bootstrap).
    #[must_use]
    pub const fn declares_public_key(&self) -> bool {
        self.public_key.is_some()
    }

    /// Retourne les bytes à hasher :
    ///
    /// ```text
    /// DOMAIN_TX_V1 || version || chain_id || nonce || sender
    /// || public_key? || gas_limit || max_fee || priority_fee
    /// || value || tx_kind || recipient || data
    /// ```
    ///
    /// La signature n'est **pas** incluse.
    #[must_use]
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut enc = Encoder::new();
        enc.write_raw(domain::TX_V1);
        self.encode_unsigned(&mut enc);
        enc.into_bytes()
    }

    /// Hash canonique de la transaction :
    ///
    /// ```text
    /// tx_hash = Keccak256(signing_payload())
    /// ```
    #[must_use]
    pub fn hash(&self) -> Hash32 {
        keccak256(&self.signing_payload())
    }

    /// Signe la transaction avec `keypair`.
    ///
    /// Retourne une copie avec la signature renseignée.
    #[must_use]
    pub fn sign(&self, keypair: &NativeKeypair) -> Self {
        let sig = sign_native(keypair, domain::TX_V1, &self.encode_unsigned_to_vec());
        let mut out = self.clone();
        out.signature = sig;
        out
    }

    /// Vérifie la signature contre `public_key`.
    pub fn verify(&self, public_key: &PublicKey) -> Result<(), CryptoError> {
        verify_native(
            public_key,
            domain::TX_V1,
            &self.encode_unsigned_to_vec(),
            &self.signature,
        )
    }

    /// Encode les champs **sans** la signature.
    #[must_use]
    pub fn encode_unsigned_to_vec(&self) -> Vec<u8> {
        let mut enc = Encoder::new();
        self.encode_unsigned(&mut enc);
        enc.into_bytes()
    }

    fn encode_unsigned(&self, enc: &mut Encoder) {
        self.version.encode(enc);
        self.chain_id.encode(enc);
        self.nonce.encode(enc);
        self.sender.encode(enc);
        self.public_key.encode(enc);
        self.gas_limit.encode(enc);
        self.max_fee.encode(enc);
        self.priority_fee.encode(enc);
        self.value.encode(enc);
        self.tx_kind.encode(enc);
        self.recipient.encode(enc);
        self.data.encode(enc);
    }
}

impl Encode for TxKind {
    fn encode(&self, enc: &mut Encoder) {
        enc.write_u8(self.tag());
    }
}

impl Decode for TxKind {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let tag = dec.read_u8()?;
        Self::from_tag(tag)
    }
}

impl Encode for Transaction {
    fn encode(&self, enc: &mut Encoder) {
        self.encode_unsigned(enc);
        self.signature.encode(enc);
    }
}

impl Decode for Transaction {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            version: u32::decode(dec)?,
            chain_id: ChainId32::decode(dec)?,
            nonce: u64::decode(dec)?,
            sender: NativeAddress::decode(dec)?,
            public_key: Option::<PublicKey>::decode(dec)?,
            gas_limit: u64::decode(dec)?,
            max_fee: u128::decode(dec)?,
            priority_fee: u128::decode(dec)?,
            value: Amount::decode(dec)?,
            tx_kind: TxKind::decode(dec)?,
            recipient: Option::<NativeAddress>::decode(dec)?,
            data: Vec::<u8>::decode(dec)?,
            signature: Signature::decode(dec)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_unsigned() -> Transaction {
        Transaction {
            version: 1,
            chain_id: ChainId32::from_bytes([0x11; 32]),
            nonce: 0,
            sender: NativeAddress::from_bytes([0xaa; 20]),
            public_key: None,
            gas_limit: 21_000,
            max_fee: 20,
            priority_fee: 2,
            value: Amount::from_base_units(100_000_000),
            tx_kind: TxKind::Transfer,
            recipient: Some(NativeAddress::from_bytes([0xbb; 20])),
            data: Vec::new(),
            signature: Signature::ZERO,
        }
    }

    #[test]
    fn tx_kind_tag_roundtrip() {
        for k in [
            TxKind::Transfer,
            TxKind::ContractCall,
            TxKind::ContractCreate,
        ] {
            assert_eq!(TxKind::from_tag(k.tag()).unwrap(), k);
        }
        assert!(TxKind::from_tag(0x00).is_err());
        assert!(TxKind::from_tag(0xff).is_err());
    }

    #[test]
    fn transaction_roundtrip() {
        let tx = sample_unsigned();
        let bytes = tx.encode_to_vec();
        let decoded = Transaction::decode_exact(&bytes).unwrap();
        assert_eq!(decoded, tx);
    }

    #[test]
    fn transaction_with_declared_pubkey_roundtrip() {
        let mut tx = sample_unsigned();
        tx.public_key = Some(PublicKey::from_bytes([0xcc; 32]));
        let bytes = tx.encode_to_vec();
        let decoded = Transaction::decode_exact(&bytes).unwrap();
        assert_eq!(decoded.public_key, Some(PublicKey::from_bytes([0xcc; 32])));
    }

    #[test]
    fn recipient_none_roundtrip() {
        let mut tx = sample_unsigned();
        tx.tx_kind = TxKind::ContractCreate;
        tx.recipient = None;
        let bytes = tx.encode_to_vec();
        let decoded = Transaction::decode_exact(&bytes).unwrap();
        assert_eq!(decoded.recipient, None);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let pk = kp.public_key();
        let mut tx = sample_unsigned();
        tx.sender = NativeAddress::from_bytes([0x00; 20]);
        let signed = tx.sign(&kp);
        assert!(signed.verify(&pk).is_ok());
    }

    #[test]
    fn verify_rejects_modified_field() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let pk = kp.public_key();
        let signed = sample_unsigned().sign(&kp);
        let mut tampered = signed.clone();
        tampered.value = Amount::from_base_units(1);
        assert!(tampered.verify(&pk).is_err());
    }

    #[test]
    fn verify_rejects_added_public_key() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let pk = kp.public_key();
        let signed = sample_unsigned().sign(&kp);
        let mut tampered = signed.clone();
        tampered.public_key = Some(PublicKey::from_bytes([0xff; 32]));
        // Le public_key est dans les bytes signés, donc la signature ne
        // vérifie plus.
        assert!(tampered.verify(&pk).is_err());
    }

    #[test]
    fn tx_hash_is_deterministic() {
        let tx = sample_unsigned();
        assert_eq!(tx.hash(), tx.hash());
    }

    #[test]
    fn tx_hash_changes_with_field() {
        let tx = sample_unsigned();
        let a = tx.hash();
        let mut t2 = tx.clone();
        t2.nonce = 1;
        assert_ne!(a, t2.hash());
    }

    #[test]
    fn tx_hash_changes_with_public_key() {
        let tx = sample_unsigned();
        let a = tx.hash();
        let mut t2 = tx.clone();
        t2.public_key = Some(PublicKey::from_bytes([0xcc; 32]));
        assert_ne!(a, t2.hash());
    }

    #[test]
    fn tx_hash_ignores_signature() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let tx = sample_unsigned();
        let signed = tx.sign(&kp);
        assert_eq!(tx.hash(), signed.hash());
    }

    #[test]
    fn declares_public_key_flag() {
        let tx = sample_unsigned();
        assert!(!tx.declares_public_key());
        let mut tx2 = tx;
        tx2.public_key = Some(PublicKey::from_bytes([0x11; 32]));
        assert!(tx2.declares_public_key());
    }
}
