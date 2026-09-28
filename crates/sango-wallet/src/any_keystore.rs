//! Abstraction multi-format sur les keyfiles V1 / V2 / V3.
//!
//! ## Rôle
//!
//! La CLI doit fonctionner indifféremment sur les trois formats sans
//! dupliquer la logique. [`AnyKeyFile`] encapsule la détection et
//! expose une API uniforme :
//!
//! - `load(path, kdf_passphrase) -> Self`
//! - `version() -> KeyFileVersion`
//! - `bip39_passphrase_used() -> bool`
//! - `sango_keypair(account, bip39_passphrase) -> NativeKeypair`
//! - `evm_keypair(account, bip39_passphrase) -> EvmKeypair`
//! - `address(account, bip39_passphrase) -> NativeAddress`
//! - `evm_address(account, bip39_passphrase) -> EvmAddress`
//! - `mnemonic_owned() -> Option<Zeroizing<String>>` (V3 uniquement)
//!
//! ## Deux secrets distincts
//!
//! - **KDF passphrase** : mot de passe de chiffrement du keyfile.
//!   Nécessaire à [`Self::load`]. Ignoré pour V1 (non chiffré).
//! - **BIP-39 passphrase** : 25ᵉ mot de la mnemonic. Nécessaire à la
//!   **dérivation** pour V3. Jamais stockée, jamais dans les arguments
//!   CLI, jamais dans une variable d'environnement.
//!
//! ## Pas de migration automatique
//!
//! Cette abstraction **lit** les trois formats. Elle ne migre **jamais**
//! V1 → V3 ou V2 → V3 automatiquement. La décision de migrer appartient
//! à l'utilisateur, via des commandes dédiées (W4.c).

use std::path::Path;

use sango_crypto::NativeKeypair;
use sango_primitives::{EvmAddress, NativeAddress};
use zeroize::Zeroizing;

use crate::error::WalletError;
use crate::evm::EvmKeypair;
use crate::keystore::{KeyFile, KeyFileVersion};
use crate::keystore_v3::KeyFileV3;

/// Vue unifiée sur un keyfile V1, V2 ou V3.
pub enum AnyKeyFile {
    /// Keyfile V1 ou V2. `KeyFile` distingue via son champ `version`.
    Legacy(KeyFile),
    /// Keyfile V3 (mnemonic BIP-39 + HD).
    V3(KeyFileV3),
}

impl AnyKeyFile {
    /// Lit uniquement le champ `version` du fichier, sans le déchiffrer.
    ///
    /// Utile à la CLI pour décider si un prompt KDF est nécessaire
    /// **avant** d'appeler [`Self::load`].
    pub fn peek_version(path: &Path) -> Result<KeyFileVersion, WalletError> {
        let bytes = std::fs::read(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                WalletError::KeyfileNotFound(path.display().to_string())
            } else {
                WalletError::Io(e)
            }
        })?;
        let raw: serde_json::Value = serde_json::from_slice(&bytes)?;
        let v = raw.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
        match v {
            1 => Ok(KeyFileVersion::V1),
            2 => Ok(KeyFileVersion::V2),
            3 => Ok(KeyFileVersion::V3),
            other => Err(WalletError::InvalidKeyfile(format!(
                "unsupported version: {other}"
            ))),
        }
    }

    /// Charge un keyfile en détectant sa version.
    ///
    /// ## Paramètres
    ///
    /// - `kdf_passphrase` : mot de passe de chiffrement du keyfile.
    ///   **Ignoré** pour V1 (non chiffré).
    ///
    /// ## Note
    ///
    /// La passphrase BIP-39 (25ᵉ mot) n'est **pas** passée ici. Elle
    /// intervient à chaque appel de dérivation. Cette séparation
    /// reflète la frontière entre les deux couches cryptographiques :
    ///
    /// ```text
    /// kdf_passphrase  →  déchiffre le keyfile
    /// bip39_passphrase →  dérive le seed depuis la mnemonic
    /// ```
    pub fn load(path: &Path, kdf_passphrase: &[u8]) -> Result<Self, WalletError> {
        let bytes = std::fs::read(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                WalletError::KeyfileNotFound(path.display().to_string())
            } else {
                WalletError::Io(e)
            }
        })?;
        let raw: serde_json::Value = serde_json::from_slice(&bytes)?;
        let version = raw.get("version").and_then(|v| v.as_u64()).unwrap_or(0);

        match version {
            1 => Ok(Self::Legacy(KeyFile::load_silent(path)?)),
            2 => Ok(Self::Legacy(KeyFile::load_encrypted(path, kdf_passphrase)?)),
            3 => Ok(Self::V3(KeyFileV3::load_encrypted(
                path,
                kdf_passphrase,
                None,
            )?)),
            v => Err(WalletError::InvalidKeyfile(format!(
                "unsupported version: {v}"
            ))),
        }
    }

    /// Version du keyfile.
    #[must_use]
    pub fn version(&self) -> KeyFileVersion {
        match self {
            Self::Legacy(kf) => kf.file_version(),
            Self::V3(_) => KeyFileVersion::V3,
        }
    }

    /// Vrai si une passphrase BIP-39 non-vide est associée au wallet.
    ///
    /// V1/V2 : toujours `false` (pas de BIP-39).
    /// V3 : reflète le flag persisté au moment de la création/import.
    #[must_use]
    pub fn bip39_passphrase_used(&self) -> bool {
        match self {
            Self::Legacy(_) => false,
            Self::V3(kf) => kf.bip39_passphrase_used(),
        }
    }

    /// Dérive le keypair natif Sango à l'index d'account donné.
    ///
    /// ## `account`
    ///
    /// - V1/V2 : seul `0` est accepté. Erreur
    ///   [`WalletError::UnsupportedAccount`] pour tout autre index.
    /// - V3 : n'importe quel index `u32`.
    ///
    /// ## `bip39_passphrase`
    ///
    /// Ignorée pour V1/V2. Utilisée pour V3.
    pub fn sango_keypair(
        &self,
        account: u32,
        bip39_passphrase: Option<&str>,
    ) -> Result<NativeKeypair, WalletError> {
        match self {
            Self::Legacy(kf) => {
                if account != 0 {
                    return Err(WalletError::UnsupportedAccount {
                        format: kf.file_version(),
                        account,
                    });
                }
                kf.keypair()
            }
            Self::V3(kf) => kf.sango_keypair_with_passphrase(account, bip39_passphrase),
        }
    }

    /// Dérive le keypair EVM à l'index d'account donné.
    pub fn evm_keypair(
        &self,
        account: u32,
        bip39_passphrase: Option<&str>,
    ) -> Result<EvmKeypair, WalletError> {
        match self {
            Self::Legacy(kf) => {
                if account != 0 {
                    return Err(WalletError::UnsupportedAccount {
                        format: kf.file_version(),
                        account,
                    });
                }
                kf.evm_keypair()
            }
            Self::V3(kf) => kf.evm_keypair_with_passphrase(account, bip39_passphrase),
        }
    }

    /// Adresse native à l'index donné.
    pub fn address(
        &self,
        account: u32,
        bip39_passphrase: Option<&str>,
    ) -> Result<NativeAddress, WalletError> {
        let kp = self.sango_keypair(account, bip39_passphrase)?;
        Ok(sango_crypto::derive_native_address(&kp.public_key()))
    }

    /// Adresse EVM à l'index donné.
    pub fn evm_address(
        &self,
        account: u32,
        bip39_passphrase: Option<&str>,
    ) -> Result<EvmAddress, WalletError> {
        Ok(self.evm_keypair(account, bip39_passphrase)?.address())
    }

    /// Mnemonic en clair, si le keyfile est V3.
    ///
    /// **Sensible** : retourner uniquement à la commande
    /// `export-mnemonic`, jamais dans un contexte de log.
    #[must_use]
    pub fn mnemonic_owned(&self) -> Option<Zeroizing<String>> {
        match self {
            Self::Legacy(_) => None,
            Self::V3(kf) => Some(kf.mnemonic_owned()),
        }
    }
}

impl std::fmt::Debug for AnyKeyFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Legacy(kf) => f.debug_tuple("AnyKeyFile::Legacy").field(kf).finish(),
            Self::V3(kf) => f.debug_tuple("AnyKeyFile::V3").field(kf).finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Mnemonic de test connue.
    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /// Écrit un keyfile V1 en clair.
    fn write_v1(path: &Path) {
        KeyFile::create(path).unwrap();
    }

    /// Écrit un keyfile V3 (KDF params Argon2id par défaut).
    ///
    /// **Lent** (~1 s), mais c'est la seule voie sans toucher à
    /// l'API publique.
    fn write_v3(path: &Path, kdf_pass: &[u8]) {
        let _ = KeyFileV3::import(path, TEST_MNEMONIC, None, kdf_pass).unwrap();
    }

    // --- V1 ---------------------------------------------------------------

    #[test]
    fn v1_load_and_account_0() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("v1.json");
        write_v1(&path);

        let kf = AnyKeyFile::load(&path, b"").unwrap();
        assert_eq!(kf.version(), KeyFileVersion::V1);
        assert!(!kf.bip39_passphrase_used());
        assert!(kf.mnemonic_owned().is_none());

        let _addr = kf.address(0, None).unwrap();
    }

    #[test]
    fn v1_rejects_account_gt_0() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("v1.json");
        write_v1(&path);

        let kf = AnyKeyFile::load(&path, b"").unwrap();
        let err = kf.address(1, None).unwrap_err();
        match err {
            WalletError::UnsupportedAccount { format, account } => {
                assert_eq!(format, KeyFileVersion::V1);
                assert_eq!(account, 1);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    // --- V3 ---------------------------------------------------------------

    #[test]
    fn v3_load_and_account_0() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("v3.json");
        write_v3(&path, b"pass");

        let kf = AnyKeyFile::load(&path, b"pass").unwrap();
        assert_eq!(kf.version(), KeyFileVersion::V3);
        assert!(!kf.bip39_passphrase_used());
        assert!(kf.mnemonic_owned().is_some());
        let _ = kf.address(0, None).unwrap();
    }

    #[test]
    fn v3_supports_account_gt_0() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("v3.json");
        write_v3(&path, b"pass");

        let kf = AnyKeyFile::load(&path, b"pass").unwrap();
        let a0 = kf.address(0, None).unwrap();
        let a1 = kf.address(1, None).unwrap();
        assert_ne!(a0, a1);
    }

    #[test]
    fn v3_bip39_passphrase_changes_address() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("v3.json");
        write_v3(&path, b"pass");

        let kf = AnyKeyFile::load(&path, b"pass").unwrap();
        let a_none = kf.address(0, None).unwrap();
        let a_pass = kf.address(0, Some("TREZOR")).unwrap();
        assert_ne!(a_none, a_pass);
    }

    #[test]
    fn v3_evm_address_differs_from_sango() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("v3.json");
        write_v3(&path, b"pass");

        let kf = AnyKeyFile::load(&path, b"pass").unwrap();
        let sango_addr = kf.address(0, None).unwrap();
        let evm_addr = kf.evm_address(0, None).unwrap();
        assert_ne!(sango_addr.as_bytes(), evm_addr.as_bytes());
    }

    #[test]
    fn v3_wrong_kdf_passphrase_fails() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("v3.json");
        write_v3(&path, b"pass");

        let err = AnyKeyFile::load(&path, b"wrong").unwrap_err();
        assert!(matches!(err, WalletError::InvalidPassphrase));
    }

    // --- Détection --------------------------------------------------------

    #[test]
    fn rejects_unknown_version() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("weird.json");
        std::fs::write(&path, r#"{"version": 99}"#).unwrap();

        let err = AnyKeyFile::load(&path, b"").unwrap_err();
        assert!(matches!(err, WalletError::InvalidKeyfile(_)));
    }

    #[test]
    fn rejects_missing_file() {
        let err = AnyKeyFile::load(Path::new("/nonexistent/x.json"), b"").unwrap_err();
        assert!(matches!(err, WalletError::KeyfileNotFound(_)));
    }
}
