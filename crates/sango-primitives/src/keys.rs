//! Types de clés et signatures natifs Sango (Ed25519).

use crate::bytes::define_fixed_bytes;

define_fixed_bytes!(
    PublicKey,
    32,
    "Clé publique Ed25519 (32 bytes) utilisée pour les comptes natifs et \
     les validateurs Sango.\n\n\
     Une implémentation NE DOIT PAS réimplémenter Ed25519 ; voir \
     `sango-crypto` pour les opérations de signature."
);

define_fixed_bytes!(
    Signature,
    64,
    "Signature Ed25519 (64 bytes) sur un message natif Sango.\n\n\
     Le message signé DOIT être préfixé par un domain separator \
     (`SANGO/TX/V1`, `SANGO/PREVOTE/V1`, etc.)."
);

#[cfg(test)]
mod tests {
    use super::{PublicKey, Signature};

    #[test]
    fn sizes_match_freeze() {
        assert_eq!(PublicKey::LEN, 32);
        assert_eq!(Signature::LEN, 64);
    }

    #[test]
    fn roundtrip_public_key() {
        let raw = [0x11u8; 32];
        let pk = PublicKey::from_bytes(raw);
        assert_eq!(pk.to_bytes(), raw);
        assert_eq!(PublicKey::from_slice(&raw).unwrap(), pk);
    }

    #[test]
    fn roundtrip_signature() {
        let raw = [0x22u8; 64];
        let sig = Signature::from_bytes(raw);
        assert_eq!(sig.to_bytes(), raw);
        assert_eq!(Signature::from_slice(&raw).unwrap(), sig);
    }

    #[test]
    fn wrong_length_rejected() {
        assert!(PublicKey::from_slice(&[0u8; 31]).is_err());
        assert!(PublicKey::from_slice(&[0u8; 33]).is_err());
        assert!(Signature::from_slice(&[0u8; 63]).is_err());
        assert!(Signature::from_slice(&[0u8; 65]).is_err());
    }
}
