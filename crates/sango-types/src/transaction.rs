//! Transaction native Sango V1.

use sango_codec::{CodecError, Decode, Decoder, Encode, Encoder};
use sango_crypto::{domain, keccak256, sign_native, verify_native, CryptoError, NativeKeypair};
use sango_primitives::{Amount, ChainId32, Hash32, NativeAddress, PublicKey, Signature};

/// Type de transaction native.
///
/// ## Tags canoniques
///
/// Les tags `0x01` à `0x03` sont **normatifs** (Freeze section 21).
/// Les tags `0x04` à `0x0B` étendent V1 pour le staking natif.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TxKind {
    /// Transfert de SANGO entre deux comptes natifs.
    Transfer = 0x01,
    /// Appel d'un contrat EVM.
    ContractCall = 0x02,
    /// Création d'un contrat EVM.
    ContractCreate = 0x03,
    /// Self-stake du compte émetteur (min 100 000 SANGO).
    Bond = 0x04,
    /// Retrait du self-stake (déclenche unbonding 14 jours).
    Unbond = 0x05,
    /// Délégation de `value` au validateur `recipient`.
    Delegate = 0x06,
    /// Retrait d'une délégation (déclenche unbonding 14 jours).
    Undelegate = 0x07,
    /// Réclamation des récompenses accumulées auprès d'un validateur.
    ClaimRewards = 0x08,
    /// Enregistrement initial d'un validateur.
    ///
    /// `data = commission_bps(4 BE) || public_key(32)`.
    RegisterValidator = 0x09,
    /// Modification de la commission d'un validateur.
    ///
    /// `data = new_commission_bps(4 BE)`. Prend effet après un délai de
    /// 7 jours.
    UpdateCommission = 0x0A,
    /// Sortie de jail après une période de downtime écoulée.
    Unjail = 0x0B,
}

impl TxKind {
    /// Tag canonique (`u8`).
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Parse un tag canonique.
    pub fn from_tag(tag: u8) -> Result<Self, CodecError> {
        match tag {
            0x01 => Ok(TxKind::Transfer),
            0x02 => Ok(TxKind::ContractCall),
            0x03 => Ok(TxKind::ContractCreate),
            0x04 => Ok(TxKind::Bond),
            0x05 => Ok(TxKind::Unbond),
            0x06 => Ok(TxKind::Delegate),
            0x07 => Ok(TxKind::Undelegate),
            0x08 => Ok(TxKind::ClaimRewards),
            0x09 => Ok(TxKind::RegisterValidator),
            0x0A => Ok(TxKind::UpdateCommission),
            0x0B => Ok(TxKind::Unjail),
            other => Err(CodecError::InvalidTag { tag: other }),
        }
    }

    /// Vrai s'il s'agit d'un `TxKind` de staking natif.
    #[must_use]
    pub const fn is_staking(self) -> bool {
        matches!(
            self,
            TxKind::Bond
                | TxKind::Unbond
                | TxKind::Delegate
                | TxKind::Undelegate
                | TxKind::ClaimRewards
                | TxKind::RegisterValidator
                | TxKind::UpdateCommission
                | TxKind::Unjail
        )
    }
}

/// Transaction native Sango V1.
///
/// Voir le Freeze section 21 pour l'ordre canonique.
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
    /// Clé publique Ed25519, si déclarée (bootstrap).
    pub public_key: Option<PublicKey>,
    /// Limite de gas.
    pub gas_limit: u64,
    /// Prix maximum par unité de gas.
    pub max_fee: u128,
    /// Pourboire par unité de gas.
    pub priority_fee: u128,
    /// Montant transféré (base units). Peut être 0.
    pub value: Amount,
    /// Type de transaction.
    pub tx_kind: TxKind,
    /// Destinataire. Voir les règles de `TxKind`.
    pub recipient: Option<NativeAddress>,
    /// Données additionnelles. Voir les règles de `TxKind`.
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

    /// Vrai s'il s'agit d'un `TxKind` de staking natif.
    #[must_use]
    pub const fn is_staking(&self) -> bool {
        self.tx_kind.is_staking()
    }

    /// Retourne les bytes à hasher.
    #[must_use]
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut enc = Encoder::new();
        enc.write_raw(domain::TX_V1);
        self.encode_unsigned(&mut enc);
        enc.into_bytes()
    }

    /// Hash canonique.
    #[must_use]
    pub fn hash(&self) -> Hash32 {
        keccak256(&self.signing_payload())
    }

    /// Signe la transaction avec `keypair`.
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
    fn all_tx_kind_tags_roundtrip() {
        for k in [
            TxKind::Transfer,
            TxKind::ContractCall,
            TxKind::ContractCreate,
            TxKind::Bond,
            TxKind::Unbond,
            TxKind::Delegate,
            TxKind::Undelegate,
            TxKind::ClaimRewards,
            TxKind::RegisterValidator,
            TxKind::UpdateCommission,
            TxKind::Unjail,
        ] {
            assert_eq!(TxKind::from_tag(k.tag()).unwrap(), k);
        }
    }

    #[test]
    fn invalid_tx_kind_rejected() {
        assert!(TxKind::from_tag(0x00).is_err());
        assert!(TxKind::from_tag(0xff).is_err());
    }

    #[test]
    fn is_staking_classifies_correctly() {
        assert!(!TxKind::Transfer.is_staking());
        assert!(!TxKind::ContractCall.is_staking());
        assert!(!TxKind::ContractCreate.is_staking());
        assert!(TxKind::Bond.is_staking());
        assert!(TxKind::Unbond.is_staking());
        assert!(TxKind::Delegate.is_staking());
        assert!(TxKind::Undelegate.is_staking());
        assert!(TxKind::ClaimRewards.is_staking());
        assert!(TxKind::RegisterValidator.is_staking());
        assert!(TxKind::UpdateCommission.is_staking());
        assert!(TxKind::Unjail.is_staking());
    }

    #[test]
    fn transaction_roundtrip() {
        let tx = sample_unsigned();
        let bytes = tx.encode_to_vec();
        let decoded = Transaction::decode_exact(&bytes).unwrap();
        assert_eq!(decoded, tx);
    }

    #[test]
    fn staking_transaction_roundtrip() {
        let mut tx = sample_unsigned();
        tx.tx_kind = TxKind::Delegate;
        tx.value = Amount::from_sango(1000).unwrap();
        tx.data = Vec::new();
        let bytes = tx.encode_to_vec();
        let decoded = Transaction::decode_exact(&bytes).unwrap();
        assert_eq!(decoded, tx);
    }

    #[test]
    fn hash_is_deterministic() {
        let tx = sample_unsigned();
        assert_eq!(tx.hash(), tx.hash());
    }

    /// **Golden vector** pour le codec TS.
    ///
    /// Valeurs figées. Toute divergence TS ↔ Rust casse ce test.
    #[test]
    fn golden_vector_fixed_transaction() {
        use sango_primitives::Signature;

        let tx = Transaction {
            version: 1,
            chain_id: ChainId32::from_bytes([0x11; 32]),
            nonce: 42,
            sender: NativeAddress::from_bytes([0xaa; 20]),
            public_key: None,
            gas_limit: 21_000,
            max_fee: 20,
            priority_fee: 2,
            value: Amount::from_base_units(100),
            tx_kind: TxKind::Transfer,
            recipient: Some(NativeAddress::from_bytes([0xbb; 20])),
            data: Vec::new(),
            signature: Signature::ZERO,
        };

        let unsigned = tx.encode_unsigned_to_vec();
        let full = tx.encode_to_vec();
        let hash = tx.hash();

        assert_eq!(unsigned.len(), 147, "taille unsigned");
        assert_eq!(full.len(), 211, "taille complète");

        // --- Hash figé (golden vector partagé avec le codec TS) ---
        assert_eq!(
            hash.to_hex(),
            "59e52128cf567408e038a076e15f575b0a505657f8e0bb885d5e12359b09aaf0"
        );

        // --- Encodage unsigned figé (147 bytes) ---
        assert_eq!(
            hex::encode(&unsigned),
            "010000001111111111111111111111111111111111111111111111111111111111111111\
             2a00000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000852000000000000\
             140000000000000000000000000000000200000000000000000000000000000064000000\
             0000000000000000000000000101bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb00000000"
        );

        // --- Encodage complet figé (211 bytes = unsigned + 64 × 0x00) ---
        let expected_full = format!(
            "{}{}",
            hex::encode(&unsigned),
            "0".repeat(128) // 64 bytes de signature ZERO
        );
        assert_eq!(hex::encode(&full), expected_full);

        // --- Vérifications structurelles par offset ---
        assert_eq!(&unsigned[0..4], &1u32.to_le_bytes());
        assert_eq!(&unsigned[4..36], &[0x11; 32]);
        assert_eq!(&unsigned[36..44], &42u64.to_le_bytes());
        assert_eq!(&unsigned[44..64], &[0xaa; 20]);
        assert_eq!(unsigned[64], 0x00); // Option None
        assert_eq!(&unsigned[65..73], &21_000u64.to_le_bytes());
        assert_eq!(&unsigned[73..89], &20u128.to_le_bytes());
        assert_eq!(&unsigned[89..105], &2u128.to_le_bytes());
        assert_eq!(&unsigned[105..121], &100u128.to_le_bytes());
        assert_eq!(unsigned[121], 0x01); // TxKind::Transfer
        assert_eq!(unsigned[122], 0x01); // Option Some
        assert_eq!(&unsigned[123..143], &[0xbb; 20]);
        assert_eq!(&unsigned[143..147], &0u32.to_le_bytes()); // data vide
    }

    #[test]
    fn sign_verify_roundtrip() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let pk = kp.public_key();
        let tx = sample_unsigned().sign(&kp);
        assert!(tx.verify(&pk).is_ok());
    }
}
