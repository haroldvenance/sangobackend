//! Compte natif Sango (`NativeAccount`).

use sango_codec::{CodecError, Decode, Decoder, Encode, Encoder};
use sango_crypto::derive_native_address;
use sango_primitives::{Amount, NativeAddress, PublicKey};

/// Compte natif Sango V1.
///
/// ## Champs
///
/// - `address` : adresse native dérivée de `public_key` ;
/// - `public_key` : clé publique Ed25519 — **donnée consensus-critical**
///   utilisée pour vérifier les signatures des transactions émises par ce
///   compte ;
/// - `balance` : solde en base units ;
/// - `nonce` : compteur de transactions émises.
///
/// ## Ordre canonique d'encodage
///
/// ```text
/// address || public_key || balance || nonce
/// ```
///
/// Soit 20 + 32 + 16 + 8 = **76 bytes fixes**.
///
/// ## Sentinel `PublicKey::ZERO`
///
/// Un compte peut exister sans que sa clé publique ne soit encore
/// enregistrée — par exemple si le compte a été crédité par un transfert
/// entrant avant que son propriétaire ne l'ait activé. Dans ce cas,
/// `public_key == PublicKey::ZERO`.
///
/// Un tel compte **ne peut pas** émettre de transaction tant que sa clé
/// publique n'a pas été enregistrée : la vérification de signature rejette
/// explicitement `PublicKey::ZERO`.
///
/// Le mécanisme exact d'enregistrement d'une clé publique lors de la
/// première transaction (bootstrap) est **à spécifier** ; voir la
/// documentation de `sango-tx`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Default)]
pub struct NativeAccount {
    /// Adresse native du compte.
    pub address: NativeAddress,
    /// Clé publique Ed25519. `PublicKey::ZERO` = non enregistrée.
    pub public_key: PublicKey,
    /// Solde en base units.
    pub balance: Amount,
    /// Compteur de transactions émises.
    pub nonce: u64,
}

impl NativeAccount {
    /// Construit un compte à partir d'une clé publique.
    ///
    /// L'adresse est **dérivée automatiquement** :
    ///
    /// ```text
    /// address = derive_native_address(public_key)
    /// ```
    ///
    /// C'est le constructeur canonique pour un compte actif.
    #[must_use]
    pub fn from_public_key(public_key: PublicKey, balance: Amount, nonce: u64) -> Self {
        let address = derive_native_address(&public_key);
        Self {
            address,
            public_key,
            balance,
            nonce,
        }
    }

    /// Vrai si la clé publique du compte a été enregistrée.
    ///
    /// Un compte « fantôme » (créé par un crédit entrant) n'a pas encore
    /// de clé publique : [`Self::has_registered_public_key`] retourne alors
    /// `false`.
    #[must_use]
    pub fn has_registered_public_key(&self) -> bool {
        !self.public_key.is_zero()
    }
}

impl Encode for NativeAccount {
    fn encode(&self, enc: &mut Encoder) {
        self.address.encode(enc);
        self.public_key.encode(enc);
        self.balance.encode(enc);
        self.nonce.encode(enc);
    }
}

impl Decode for NativeAccount {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            address: NativeAddress::decode(dec)?,
            public_key: PublicKey::decode(dec)?,
            balance: Amount::decode(dec)?,
            nonce: u64::decode(dec)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sango_crypto::NativeKeypair;
    use sango_primitives::Amount;

    fn addr(b: u8) -> NativeAddress {
        NativeAddress::from_bytes([b; 20])
    }

    #[test]
    fn account_encoding_size_is_fixed() {
        let a = NativeAccount {
            address: addr(0x11),
            public_key: PublicKey::from_bytes([0x22; 32]),
            balance: Amount::from_base_units(0),
            nonce: 0,
        };
        // 20 (address) + 32 (pubkey) + 16 (balance) + 8 (nonce) = 76
        assert_eq!(a.encode_to_vec().len(), 76);
    }

    #[test]
    fn account_roundtrip() {
        let a = NativeAccount {
            address: addr(0x11),
            public_key: PublicKey::from_bytes([0x22; 32]),
            balance: Amount::from_base_units(10_000_000),
            nonce: 42,
        };
        let bytes = a.encode_to_vec();
        let decoded = NativeAccount::decode_exact(&bytes).unwrap();
        assert_eq!(decoded, a);
    }

    #[test]
    fn account_with_zero_pubkey_roundtrip() {
        let a = NativeAccount {
            address: addr(0x11),
            public_key: PublicKey::ZERO,
            balance: Amount::from_base_units(500),
            nonce: 0,
        };
        let bytes = a.encode_to_vec();
        let decoded = NativeAccount::decode_exact(&bytes).unwrap();
        assert_eq!(decoded, a);
        assert!(!decoded.has_registered_public_key());
    }

    #[test]
    fn from_public_key_derives_address() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let pk = kp.public_key();
        let expected_address = derive_native_address(&pk);
        let a = NativeAccount::from_public_key(pk, Amount::from_base_units(100), 0);
        assert_eq!(a.address, expected_address);
        assert_eq!(a.public_key, pk);
        assert!(a.has_registered_public_key());
    }

    #[test]
    fn has_registered_public_key_detects_zero() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let real = NativeAccount::from_public_key(kp.public_key(), Amount::ZERO, 0);
        assert!(real.has_registered_public_key());

        let ghost = NativeAccount {
            address: addr(0x11),
            public_key: PublicKey::ZERO,
            balance: Amount::ZERO,
            nonce: 0,
        };
        assert!(!ghost.has_registered_public_key());
    }

    #[test]
    fn default_is_ghost_account() {
        let a = NativeAccount::default();
        assert!(!a.has_registered_public_key());
        assert_eq!(a.address, NativeAddress::ZERO);
        assert_eq!(a.balance, Amount::ZERO);
        assert_eq!(a.nonce, 0);
    }
}
