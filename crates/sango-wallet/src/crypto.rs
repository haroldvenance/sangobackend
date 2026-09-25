//! Chiffrement du keyfile : Argon2id + ChaCha20-Poly1305.
//!
//! ## Format
//!
//! ```text
//! key          = Argon2id(passphrase, salt, m=64MiB, t=3, p=4) → 32 bytes
//! nonce        = 12 bytes aléatoires (CSPRNG)
//! ciphertext   = ChaCha20Poly1305(key, nonce, plaintext, aad)
//! ```
//!
//! ## AAD (Additional Authenticated Data)
//!
//! Pour lier les métadonnées non-chiffrées (version, KDF params, etc.) au
//! ciphertext, on les passe en AAD. Toute modification d'un bit du JSON
//! externe (hors champ `ciphertext_hex`) fait échouer le déchiffrement.
//!
//! ## Effacement mémoire
//!
//! Toutes les buffers contenant la passphrase, la clé dérivée, ou le
//! plaintext sont `zeroize` explicitement.
//!
//! ## Paramètres Argon2id
//!
//! Paramètres OWASP 2024 recommandés pour un KDF de mot de passe :
//!
//! | Paramètre | Valeur | Sens |
//! |---|---|---|
//! | `m_cost` | 65536 KiB (64 MiB) | mémoire |
//! | `t_cost` | 3 | itérations |
//! | `p_cost` | 4 | parallélisme |
//!
//! Ces paramètres sont **stockés dans le keystore** (jamais codés en dur
//! côté déchiffrement), ce qui permet de les faire évoluer sans casser
//! les anciens keyfiles.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

use crate::error::WalletError;

/// Longueur du sel Argon2 (16 bytes).
pub const SALT_LEN: usize = 16;

/// Longueur du nonce ChaCha20-Poly1305 (12 bytes).
pub const NONCE_LEN: usize = 12;

/// Longueur de la clé dérivée (32 bytes pour ChaCha20).
pub const KEY_LEN: usize = 32;

/// Paramètres Argon2id stockés dans le keystore.
///
/// Les défauts correspondent à OWASP 2024.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KdfParams {
    /// Coût mémoire en KiB (64 MiB par défaut).
    pub m_cost_kib: u32,
    /// Nombre d'itérations (3 par défaut).
    pub t_cost: u32,
    /// Parallélisme (4 par défaut).
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost_kib: 65_536,
            t_cost: 3,
            p_cost: 4,
        }
    }
}

impl KdfParams {
    /// Construit les paramètres Argon2 pour la crate.
    fn build_argon2(self) -> Result<Argon2<'static>, WalletError> {
        let params = Params::new(self.m_cost_kib, self.t_cost, self.p_cost, Some(KEY_LEN))
            .map_err(|e| WalletError::Argon2(e.to_string()))?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

/// Résultat d'un chiffrement.
pub struct EncryptedBlob {
    /// Sel Argon2 (16 bytes).
    pub salt: [u8; SALT_LEN],
    /// Nonce ChaCha20 (12 bytes).
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext + tag Poly1305.
    pub ciphertext: Vec<u8>,
}

/// Dérive une clé 32-byte depuis `passphrase` et `salt`.
fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    params: &KdfParams,
) -> Result<[u8; KEY_LEN], WalletError> {
    let argon2 = params.build_argon2()?;
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| WalletError::Argon2(e.to_string()))?;
    Ok(key)
}

/// Chiffre `plaintext` avec `passphrase`.
///
/// ## AAD
///
/// `aad` est authentifié (Poly1305 tag) mais **non chiffré**. Utilisé pour
/// lier les métadonnées du keystore au ciphertext.
pub fn encrypt(
    plaintext: &[u8],
    passphrase: &[u8],
    aad: &[u8],
    params: &KdfParams,
) -> Result<EncryptedBlob, WalletError> {
    if passphrase.is_empty() {
        return Err(WalletError::EmptyPassphrase);
    }

    // 1. Générer sel + nonce via CSPRNG.
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    // 2. Dériver la clé.
    let mut key = derive_key(passphrase, &salt, params)?;

    // 3. Chiffrer avec AEAD.
    let cipher = ChaCha20Poly1305::new((&key).into());
    let nonce_ga = Nonce::from_slice(&nonce);
    let ciphertext = cipher
        .encrypt(
            nonce_ga,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| WalletError::Aead(e.to_string()))?;

    // 4. Effacer la clé.
    key.zeroize();

    Ok(EncryptedBlob {
        salt,
        nonce,
        ciphertext,
    })
}

/// Déchiffre `blob` avec `passphrase`.
///
/// Retourne le plaintext, ou [`WalletError::InvalidPassphrase`] si la
/// passphrase est incorrecte **ou** si l'AAD a été modifié.
pub fn decrypt(
    blob: &EncryptedBlob,
    passphrase: &[u8],
    aad: &[u8],
    params: &KdfParams,
) -> Result<Vec<u8>, WalletError> {
    if passphrase.is_empty() {
        return Err(WalletError::EmptyPassphrase);
    }

    let mut key = derive_key(passphrase, &blob.salt, params)?;
    let cipher = ChaCha20Poly1305::new((&key).into());
    let nonce_ga = Nonce::from_slice(&blob.nonce);
    let result = cipher
        .decrypt(
            nonce_ga,
            Payload {
                msg: &blob.ciphertext,
                aad,
            },
        )
        .map_err(|_| WalletError::InvalidPassphrase);

    key.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_params() -> KdfParams {
        // Paramètres **réduits** pour les tests : on ne veut pas payer
        // 64 MiB × plusieurs tests.
        KdfParams {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[test]
    fn roundtrip_basic() {
        let pt = b"hello, sango!";
        let pass = b"correct horse battery staple";
        let aad = b"v2|argon2id|chacha20poly1305";
        let blob = encrypt(pt, pass, aad, &fast_params()).unwrap();
        let decoded = decrypt(&blob, pass, aad, &fast_params()).unwrap();
        assert_eq!(decoded, pt);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let blob = encrypt(b"x", b"good", b"aad", &fast_params()).unwrap();
        let err = decrypt(&blob, b"bad", b"aad", &fast_params()).unwrap_err();
        assert!(matches!(err, WalletError::InvalidPassphrase));
    }

    #[test]
    fn modified_aad_fails() {
        let blob = encrypt(b"x", b"pass", b"aad1", &fast_params()).unwrap();
        let err = decrypt(&blob, b"pass", b"aad2", &fast_params()).unwrap_err();
        assert!(matches!(err, WalletError::InvalidPassphrase));
    }

    #[test]
    fn modified_ciphertext_fails() {
        let mut blob = encrypt(b"x", b"pass", b"aad", &fast_params()).unwrap();
        if !blob.ciphertext.is_empty() {
            blob.ciphertext[0] ^= 0x01;
        }
        let err = decrypt(&blob, b"pass", b"aad", &fast_params()).unwrap_err();
        assert!(matches!(err, WalletError::InvalidPassphrase));
    }

    #[test]
    fn empty_passphrase_rejected() {
        assert!(matches!(
            encrypt(b"x", b"", b"aad", &fast_params()),
            Err(WalletError::EmptyPassphrase)
        ));
    }

    #[test]
    fn encrypt_is_randomized() {
        let pass = b"pass";
        let aad = b"aad";
        let b1 = encrypt(b"x", pass, aad, &fast_params()).unwrap();
        let b2 = encrypt(b"x", pass, aad, &fast_params()).unwrap();
        // Sels et nonces aléatoires → ciphertexts différents.
        assert_ne!(b1.salt, b2.salt);
        assert_ne!(b1.nonce, b2.nonce);
        assert_ne!(b1.ciphertext, b2.ciphertext);
    }

    #[test]
    fn decrypt_detects_truncated_ciphertext() {
        let mut blob = encrypt(b"long message content", b"pass", b"aad", &fast_params()).unwrap();
        blob.ciphertext.pop();
        assert!(matches!(
            decrypt(&blob, b"pass", b"aad", &fast_params()),
            Err(WalletError::InvalidPassphrase)
        ));
    }
}
