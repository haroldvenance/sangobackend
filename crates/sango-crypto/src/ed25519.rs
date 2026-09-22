//! Signatures Ed25519 natives Sango (comptes + validateurs).
//!
//! L’algorithme lui-même est fourni par `ed25519-dalek`. Ce module
//! n’implémente **aucune** primitive cryptographique ; il adapte l’API de
//! la bibliothèque aux types de `sango-primitives` et impose la séparation
//! de domaine.

use ed25519_dalek::{Signature as DalekSig, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use sango_primitives::{PublicKey, Signature};
use thiserror::Error;

/// Erreur produite par les opérations Ed25519.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    /// La clé publique fournie n’est pas un point valide.
    #[error("invalid ed25519 public key")]
    InvalidPublicKey,

    /// La signature fournie n’a pas un format valide.
    #[error("invalid ed25519 signature encoding")]
    InvalidSignatureEncoding,

    /// La vérification a échoué.
    #[error("signature verification failed")]
    VerificationFailed,
}

/// Paire de clés Ed25519 native Sango.
#[derive(Clone)]
pub struct NativeKeypair {
    signing: SigningKey,
}

impl NativeKeypair {
    /// Génère une nouvelle paire de clés à partir du CSPRNG de l’OS.
    #[must_use]
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut OsRng),
        }
    }

    /// Construit une paire à partir d’une graine déterministe de 32 bytes.
    ///
    /// Utile pour les tests et les vecteurs normatifs. En production,
    /// préférer [`NativeKeypair::generate`].
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(&seed),
        }
    }

    /// Retourne la clé publique correspondante.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        let vk = self.signing.verifying_key();
        PublicKey::from_bytes(vk.to_bytes())
    }

    /// Signe un message brut (sans domain separator).
    ///
    /// Pour les messages de protocole, préférer [`sign_native`].
    #[must_use]
    pub fn sign_raw(&self, message: &[u8]) -> Signature {
        let sig: DalekSig = self.signing.sign(message);
        Signature::from_bytes(sig.to_bytes())
    }
}

impl core::fmt::Debug for NativeKeypair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NativeKeypair")
            .field("public_key", &self.public_key())
            .finish_non_exhaustive()
    }
}

/// Signe `domain || payload` avec `keypair` (Ed25519).
///
/// C’est la fonction normative pour les signatures natives Sango :
/// les bytes signés sont exactement `domain || payload`.
#[must_use]
pub fn sign_native(keypair: &NativeKeypair, domain: &[u8], payload: &[u8]) -> Signature {
    let mut msg = Vec::with_capacity(domain.len() + payload.len());
    msg.extend_from_slice(domain);
    msg.extend_from_slice(payload);
    keypair.sign_raw(&msg)
}

/// Vérifie une signature Ed25519 sur `domain || payload`.
///
/// Retourne `Ok(())` si la signature est valide, sinon une [`CryptoError`].
pub fn verify_native(
    public_key: &PublicKey,
    domain: &[u8],
    payload: &[u8],
    signature: &Signature,
) -> Result<(), CryptoError> {
    let vk = VerifyingKey::from_bytes(public_key.as_bytes())
        .map_err(|_| CryptoError::InvalidPublicKey)?;
    let sig = DalekSig::from_bytes(signature.as_bytes());
    let mut msg = Vec::with_capacity(domain.len() + payload.len());
    msg.extend_from_slice(domain);
    msg.extend_from_slice(payload);
    vk.verify(&msg, &sig)
        .map_err(|_| CryptoError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain;

    #[test]
    fn generate_and_sign_roundtrip() {
        let kp = NativeKeypair::generate();
        let pk = kp.public_key();
        let sig = sign_native(&kp, domain::TX_V1, b"payload");
        assert!(verify_native(&pk, domain::TX_V1, b"payload", &sig).is_ok());
    }

    #[test]
    fn wrong_payload_fails() {
        let kp = NativeKeypair::generate();
        let pk = kp.public_key();
        let sig = sign_native(&kp, domain::TX_V1, b"payload");
        assert_eq!(
            verify_native(&pk, domain::TX_V1, b"other", &sig),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn wrong_domain_fails() {
        let kp = NativeKeypair::generate();
        let pk = kp.public_key();
        let sig = sign_native(&kp, domain::TX_V1, b"payload");
        assert_eq!(
            verify_native(&pk, domain::PREVOTE_V1, b"payload", &sig),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn wrong_key_fails() {
        let kp1 = NativeKeypair::generate();
        let kp2 = NativeKeypair::generate();
        let sig = sign_native(&kp1, domain::TX_V1, b"payload");
        assert_eq!(
            verify_native(&kp2.public_key(), domain::TX_V1, b"payload", &sig),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn deterministic_from_seed() {
        let seed = [0x42u8; 32];
        let kp1 = NativeKeypair::from_seed(seed);
        let kp2 = NativeKeypair::from_seed(seed);
        assert_eq!(kp1.public_key(), kp2.public_key());
        let sig1 = sign_native(&kp1, domain::TX_V1, b"payload");
        let sig2 = sign_native(&kp2, domain::TX_V1, b"payload");
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn public_key_length_is_32() {
        let kp = NativeKeypair::generate();
        assert_eq!(kp.public_key().as_bytes().len(), 32);
    }

    #[test]
    fn signature_length_is_64() {
        let kp = NativeKeypair::generate();
        let sig = sign_native(&kp, domain::TX_V1, b"");
        assert_eq!(sig.as_bytes().len(), 64);
    }
}
