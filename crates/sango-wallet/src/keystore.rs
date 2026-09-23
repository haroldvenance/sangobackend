//! Gestion des clés du wallet.
//!
//! Les clés sont stockées dans un fichier JSON avec permissions `0600` sur
//! Unix. Le format est simple :
//!
//! ```json
//! {
//!   "version": 1,
//!   "seed_hex": "000102...",
//!   "address_hex": "abcd...",
//!   "created_at": 1700000000
//! }
//! ```
//!
//! Le `seed_hex` est la clé privée Ed25519 brute (32 bytes). Il ne doit
//! **jamais** être partagé ni commité.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use sango_crypto::{derive_native_address, NativeKeypair};
use sango_primitives::NativeAddress;

use crate::error::WalletError;

/// Contenu d'un keyfile.
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyFile {
    /// Version du format.
    pub version: u32,
    /// Graine Ed25519 encodée en hexadécimal (64 caractères).
    pub seed_hex: String,
    /// Adresse native dérivée, en hex (40 caractères).
    pub address_hex: String,
    /// Timestamp Unix de création.
    pub created_at: u64,
}

impl KeyFile {
    /// Emplacement par défaut : `~/.sango/wallet.json`.
    pub fn default_path() -> Result<PathBuf, WalletError> {
        let home = std::env::var("HOME")
            .map_err(|_| WalletError::InvalidKeyfile("$HOME not set".into()))?;
        Ok(PathBuf::from(home).join(".sango").join("wallet.json"))
    }

    /// Charge un keyfile existant.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, WalletError> {
        let path = path.as_ref();
        let bytes = fs::read(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                WalletError::KeyfileNotFound(path.display().to_string())
            } else {
                WalletError::Io(e)
            }
        })?;
        let kf: KeyFile = serde_json::from_slice(&bytes)?;
        if kf.version != 1 {
            return Err(WalletError::InvalidKeyfile(format!(
                "unsupported version: {}",
                kf.version
            )));
        }
        Ok(kf)
    }

    /// Génère un nouveau keyfile et l'écrit sur disque.
    pub fn create(path: impl AsRef<Path>) -> Result<Self, WalletError> {
        let path = path.as_ref();
        if path.exists() {
            return Err(WalletError::KeyfileExists(path.display().to_string()));
        }

        // Générer une graine Ed25519 à partir d'OsRng.
        let seed = random_seed();
        let kp = NativeKeypair::from_seed(seed);
        let address = derive_native_address(&kp.public_key());

        let kf = Self {
            version: 1,
            seed_hex: hex::encode(seed),
            address_hex: address.to_hex(),
            created_at: now_unix(),
        };

        kf.write_atomic(path)?;
        Ok(kf)
    }

    /// Reconstruit le keypair Ed25519.
    pub fn keypair(&self) -> Result<NativeKeypair, WalletError> {
        let bytes = hex::decode(&self.seed_hex)?;
        if bytes.len() != 32 {
            return Err(WalletError::InvalidKeyfile(format!(
                "seed must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        Ok(NativeKeypair::from_seed(seed))
    }

    /// Adresse native.
    pub fn address(&self) -> Result<NativeAddress, WalletError> {
        NativeAddress::from_hex(&self.address_hex)
            .map_err(|e| WalletError::InvalidKeyfile(format!("bad address: {e}")))
    }

    /// Écrit le keyfile avec permissions `0600`.
    fn write_atomic(&self, path: &Path) -> Result<(), WalletError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(self)?;
        fs::write(&tmp, &bytes)?;

        // Permissions 0600 sur Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            fs::set_permissions(&tmp, perms)?;
        }

        fs::rename(&tmp, path)?;
        Ok(())
    }
}

/// Génère 32 bytes aléatoires via le CSPRNG de l'OS.
fn random_seed() -> [u8; 32] {
    // On utilise le keypair generator de sango-crypto (qui tire d'OsRng),
    // mais on a besoin de la graine brute pour la persister. On contourne
    // en tirant depuis getrandom directement.
    // `sango-crypto` n'expose pas la graine, donc on utilise
    // `NativeKeypair::generate()` puis on en dérive un seed… sauf qu'on ne
    // peut pas extraire la graine. Solution : tirer directement.
    use rand_core::OsRng;
    use rand_core::RngCore;
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    seed
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.json");

        let kf = KeyFile::create(&path).unwrap();
        assert_eq!(kf.version, 1);
        assert_eq!(kf.seed_hex.len(), 64);
        assert_eq!(kf.address_hex.len(), 40);

        let loaded = KeyFile::load(&path).unwrap();
        assert_eq!(loaded.seed_hex, kf.seed_hex);
        assert_eq!(loaded.address_hex, kf.address_hex);
    }

    #[test]
    fn create_twice_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.json");
        KeyFile::create(&path).unwrap();
        let err = KeyFile::create(&path).unwrap_err();
        assert!(matches!(err, WalletError::KeyfileExists(_)));
    }

    #[test]
    fn load_missing_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nope.json");
        let err = KeyFile::load(&path).unwrap_err();
        assert!(matches!(err, WalletError::KeyfileNotFound(_)));
    }

    #[test]
    fn keypair_derives_same_address() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.json");
        let kf = KeyFile::create(&path).unwrap();

        let kp = kf.keypair().unwrap();
        let derived = derive_native_address(&kp.public_key());
        assert_eq!(derived.to_hex(), kf.address_hex);
        assert_eq!(derived, kf.address().unwrap());
    }

    #[test]
    fn permissions_are_0600_on_unix() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("wallet.json");
            KeyFile::create(&path).unwrap();
            let meta = fs::metadata(&path).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "expected 0600, got {:o}", mode);
        }
    }
}
