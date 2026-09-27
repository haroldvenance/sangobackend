//! Gestion des clés du wallet.
//!
//! ## Formats supportés
//!
//! ### Version 1 (clair, legacy)
//!
//! ```json
//! {
//!   "version": 1,
//!   "seed_hex": "000102...",
//!   "address_hex": "abcd...",
//!   "created_at": 1700000000,
//!   "evm_secret_hex": "..." (optionnel)
//! }
//! ```
//!
//! ⚠️ **Non sécurisé** : la seed est en clair. Conservé pour la
//! rétrocompatibilité. Un warning est émis au chargement.
//!
//! ### Version 2 (chiffré, recommandé)
//!
//! ```json
//! {
//!   "version": 2,
//!   "created_at": 1700000000,
//!   "address_hex": "abcd...",
//!   "kdf": "argon2id",
//!   "kdf_params": { "m_cost_kib": 65536, "t_cost": 3, "p_cost": 4, "salt_hex": "..." },
//!   "cipher": "chacha20poly1305",
//!   "nonce_hex": "...",
//!   "ciphertext_hex": "..."
//! }
//! ```
//!
//! Le ciphertext contient (JSON, AEAD-authentifié) :
//!
//! ```json
//! { "seed_hex": "...", "evm_secret_hex": "..." (optionnel) }
//! ```
//!
//! Les métadonnées (KDF params, cipher) sont en AAD : tout bit modifié
//! dans le JSON externe fait échouer le déchiffrement.
//!
//! ## Permissions
//!
//! `0600` sur Unix, écriture atomique (tempfile + rename).
//!
//! ## Effacement mémoire
//!
//! Les buffers contenant la seed, la clé EVM, ou la passphrase sont
//! `zeroize` explicitement.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use sango_crypto::{derive_native_address, NativeKeypair};
use sango_primitives::NativeAddress;

use crate::crypto::{self, EncryptedBlob, KdfParams, NONCE_LEN, SALT_LEN};
use crate::error::WalletError;

// --- Format JSON externe (désérialisation brute) --------------------------

/// Structure brute du JSON, selon la version.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawKeyFile {
    V1(RawV1),
    V2(RawV2),
}

#[derive(Debug, Deserialize, Serialize)]
struct RawV1 {
    version: u32,
    seed_hex: String,
    address_hex: String,
    created_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    evm_secret_hex: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RawV2 {
    version: u32,
    created_at: u64,
    address_hex: String,
    kdf: String,
    kdf_params: RawKdfParams,
    cipher: String,
    nonce_hex: String,
    ciphertext_hex: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct RawKdfParams {
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
    salt_hex: String,
}

/// Contenu **déchiffré** d'un keyfile v2.
#[derive(Debug, Serialize, Deserialize)]
struct Plaintext {
    seed_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    evm_secret_hex: Option<String>,
}

// --- KeyFile (API publique) -----------------------------------------------

/// Keyfile en mémoire, après déchiffrement éventuel.
///
/// Contient les secrets **en clair** (en mémoire). Les buffers sont
/// effacés au `Drop`.
pub struct KeyFile {
    /// Version du format (1 ou 2).
    pub version: u32,
    /// Graine Ed25519 (32 bytes).
    pub seed_hex: String,
    /// Adresse native dérivée.
    pub address_hex: String,
    /// Timestamp Unix de création.
    pub created_at: u64,
    /// Secret secp256k1 EVM (32 bytes hex), optionnel.
    pub evm_secret_hex: Option<String>,
    /// Paramètres KDF utilisés pour le chiffrement (None si v1).
    ///
    /// Stockés ici pour pouvoir **réécrire** le keystore avec les mêmes
    /// params lors d'un `attach_evm_key`.
    pub kdf_params: Option<KdfParams>,
}

impl Drop for KeyFile {
    fn drop(&mut self) {
        self.seed_hex.zeroize();
        if let Some(s) = self.evm_secret_hex.as_mut() {
            s.zeroize();
        }
    }
}

impl std::fmt::Debug for KeyFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyFile")
            .field("version", &self.version)
            .field("address_hex", &self.address_hex)
            .field("created_at", &self.created_at)
            .field("has_evm_key", &self.evm_secret_hex.is_some())
            .finish_non_exhaustive()
    }
}

impl KeyFile {
    /// Emplacement par défaut : `~/.sango/wallet.json`.
    pub fn default_path() -> Result<PathBuf, WalletError> {
        let home = std::env::var("HOME")
            .map_err(|_| WalletError::InvalidKeyfile("$HOME not set".into()))?;
        Ok(PathBuf::from(home).join(".sango").join("wallet.json"))
    }

    /// Charge un keyfile **v1 en clair**, avec avertissement de sécurité.
    ///
    /// Réservé aux commandes qui **signent** ou **modifient** le keyfile.
    /// Pour les lectures publiques (adresse, solde, historique), utiliser
    /// [`Self::load_silent`] — le warning y serait du bruit.
    ///
    /// # Erreurs
    ///
    /// [`WalletError::AlreadyEncrypted`] si le fichier est en v2 — il
    /// faut alors utiliser [`Self::load_encrypted`].
    pub fn load(path: impl AsRef<Path>) -> Result<Self, WalletError> {
        let kf = Self::load_silent(path)?;
        if kf.version == 1 {
            eprintln!("⚠️  Keyfile en clair (v1). Migrez avec `sango-wallet keyfile encrypt`.");
        }
        Ok(kf)
    }

    /// Charge un keyfile **v1 en clair**, sans warning.
    ///
    /// À utiliser pour les commandes qui ne manipulent que des données
    /// publiques (adresse, solde, historique). Pour les commandes
    /// sensibles, préférer [`Self::load`].
    pub fn load_silent(path: impl AsRef<Path>) -> Result<Self, WalletError> {
        let path = path.as_ref();
        let bytes = fs::read(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                WalletError::KeyfileNotFound(path.display().to_string())
            } else {
                WalletError::Io(e)
            }
        })?;
        let raw: RawKeyFile = serde_json::from_slice(&bytes)?;
        match raw {
            RawKeyFile::V1(v1) => {
                if v1.version != 1 {
                    return Err(WalletError::InvalidKeyfile(format!(
                        "unsupported version: {}",
                        v1.version
                    )));
                }
                Ok(Self {
                    version: 1,
                    seed_hex: v1.seed_hex,
                    address_hex: v1.address_hex,
                    created_at: v1.created_at,
                    evm_secret_hex: v1.evm_secret_hex,
                    kdf_params: None,
                })
            }
            RawKeyFile::V2(_) => Err(WalletError::AlreadyEncrypted),
        }
    }

    /// Charge un keyfile **v2 chiffré** avec la passphrase.
    pub fn load_encrypted(path: impl AsRef<Path>, passphrase: &[u8]) -> Result<Self, WalletError> {
        let path = path.as_ref();
        let bytes = fs::read(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                WalletError::KeyfileNotFound(path.display().to_string())
            } else {
                WalletError::Io(e)
            }
        })?;
        let raw: RawKeyFile = serde_json::from_slice(&bytes)?;
        let RawKeyFile::V2(v2) = raw else {
            return Err(WalletError::NotEncrypted);
        };
        if v2.version != 2 {
            return Err(WalletError::InvalidKeyfile(format!(
                "unsupported v2 sub-version: {}",
                v2.version
            )));
        }
        if v2.kdf != "argon2id" {
            return Err(WalletError::InvalidKeyfile(format!(
                "unsupported kdf: {}",
                v2.kdf
            )));
        }
        if v2.cipher != "chacha20poly1305" {
            return Err(WalletError::InvalidKeyfile(format!(
                "unsupported cipher: {}",
                v2.cipher
            )));
        }

        let salt = hex_to_fixed::<SALT_LEN>(&v2.kdf_params.salt_hex, "salt")?;
        let nonce = hex_to_fixed::<NONCE_LEN>(&v2.nonce_hex, "nonce")?;
        let ciphertext = hex::decode(&v2.ciphertext_hex)?;

        let params = KdfParams {
            m_cost_kib: v2.kdf_params.m_cost_kib,
            t_cost: v2.kdf_params.t_cost,
            p_cost: v2.kdf_params.p_cost,
        };

        let aad = build_aad(&v2);

        let blob = EncryptedBlob {
            salt,
            nonce,
            ciphertext,
        };
        let mut plaintext_bytes = crypto::decrypt(&blob, passphrase, &aad, &params)?;
        let plain: Plaintext = serde_json::from_slice(&plaintext_bytes)
            .map_err(|e| WalletError::InvalidKeyfile(format!("plaintext: {e}")))?;
        plaintext_bytes.zeroize();

        Ok(Self {
            version: 2,
            seed_hex: plain.seed_hex,
            address_hex: v2.address_hex,
            created_at: v2.created_at,
            evm_secret_hex: plain.evm_secret_hex,
            kdf_params: Some(params),
        })
    }

    /// Charge un keyfile **en détectant** la version. Si v2, la
    /// passphrase doit être fournie.
    pub fn load_any(
        path: impl AsRef<Path>,
        passphrase: Option<&[u8]>,
    ) -> Result<Self, WalletError> {
        let path = path.as_ref();
        let bytes = fs::read(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                WalletError::KeyfileNotFound(path.display().to_string())
            } else {
                WalletError::Io(e)
            }
        })?;
        let raw: RawKeyFile = serde_json::from_slice(&bytes)?;
        match raw {
            RawKeyFile::V1(_) => Self::load(path),
            RawKeyFile::V2(_) => {
                let pass = passphrase.ok_or(WalletError::EmptyPassphrase)?;
                Self::load_encrypted(path, pass)
            }
        }
    }

    /// Génère un nouveau keyfile **v1 en clair** et l'écrit sur disque.
    ///
    /// Pour un keyfile chiffré, utiliser [`Self::create_encrypted`].
    pub fn create(path: impl AsRef<Path>) -> Result<Self, WalletError> {
        let path = path.as_ref();
        if path.exists() {
            return Err(WalletError::KeyfileExists(path.display().to_string()));
        }

        let seed = random_seed();
        let kp = NativeKeypair::from_seed(seed);
        let address = derive_native_address(&kp.public_key());

        let kf = Self {
            version: 1,
            seed_hex: hex::encode(seed),
            address_hex: address.to_hex(),
            created_at: now_unix(),
            evm_secret_hex: None,
            kdf_params: None,
        };

        kf.write_v1(path)?;
        Ok(kf)
    }

    /// Génère un nouveau keyfile **v2 chiffré** et l'écrit sur disque.
    pub fn create_encrypted(
        path: impl AsRef<Path>,
        passphrase: &[u8],
    ) -> Result<Self, WalletError> {
        let path = path.as_ref();
        if path.exists() {
            return Err(WalletError::KeyfileExists(path.display().to_string()));
        }
        if passphrase.is_empty() {
            return Err(WalletError::EmptyPassphrase);
        }

        let seed = random_seed();
        let kp = NativeKeypair::from_seed(seed);
        let address = derive_native_address(&kp.public_key());

        let kf = Self {
            version: 2,
            seed_hex: hex::encode(seed),
            address_hex: address.to_hex(),
            created_at: now_unix(),
            evm_secret_hex: None,
            kdf_params: Some(KdfParams::default()),
        };

        kf.write_v2(path, passphrase)?;
        Ok(kf)
    }

    // --- Accès clés --------------------------------------------------------

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
        let kp = NativeKeypair::from_seed(seed);
        seed.zeroize();
        Ok(kp)
    }

    /// Clé publique Ed25519 encodée en hex (64 caractères).
    pub fn public_key_hex(&self) -> Result<String, WalletError> {
        let kp = self.keypair()?;
        Ok(kp.public_key().to_hex())
    }

    /// Clé publique Ed25519.
    pub fn public_key(&self) -> Result<sango_primitives::PublicKey, WalletError> {
        Ok(self.keypair()?.public_key())
    }

    /// Adresse native.
    pub fn address(&self) -> Result<NativeAddress, WalletError> {
        NativeAddress::from_hex(&self.address_hex)
            .map_err(|e| WalletError::InvalidKeyfile(format!("bad address: {e}")))
    }

    // --- EVM ---------------------------------------------------------------

    /// Vrai si une clé EVM est attachée.
    #[must_use]
    pub fn has_evm_key(&self) -> bool {
        self.evm_secret_hex.is_some()
    }

    /// Génère et attache une clé EVM, puis réécrit le keyfile.
    ///
    /// - v1 → réécrit en clair (⚠️ avertissement).
    /// - v2 → exige la passphrase pour réécrire.
    pub fn attach_evm_key(
        &mut self,
        path: &Path,
        passphrase: Option<&[u8]>,
    ) -> Result<(), WalletError> {
        if self.evm_secret_hex.is_some() {
            return Err(WalletError::InvalidKeyfile(
                "EVM key already present".into(),
            ));
        }
        let kp = crate::evm::EvmKeypair::generate();
        self.evm_secret_hex = Some(hex::encode(kp.secret_bytes()));

        match self.version {
            1 => self.write_v1(path)?,
            2 => {
                let pass = passphrase.ok_or(WalletError::EmptyPassphrase)?;
                self.write_v2(path, pass)?;
            }
            v => {
                return Err(WalletError::InvalidKeyfile(format!(
                    "unsupported version: {v}"
                )))
            }
        }
        Ok(())
    }

    /// Reconstruit la paire de clés EVM.
    pub fn evm_keypair(&self) -> Result<crate::evm::EvmKeypair, WalletError> {
        let hex_str = self
            .evm_secret_hex
            .as_ref()
            .ok_or_else(|| WalletError::InvalidKeyfile("no EVM key in keyfile".into()))?;
        let bytes = hex::decode(hex_str)?;
        if bytes.len() != 32 {
            return Err(WalletError::InvalidKeyfile(format!(
                "EVM secret must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&bytes);
        let kp = crate::evm::EvmKeypair::from_secret(secret);
        secret.zeroize();
        kp
    }

    /// Adresse EVM locale.
    pub fn evm_address(&self) -> Result<sango_primitives::EvmAddress, WalletError> {
        Ok(self.evm_keypair()?.address())
    }

    // --- Migration ---------------------------------------------------------

    /// Chiffre un keyfile v1 (en place) et retourne le KeyFile v2.
    ///
    /// # Erreurs
    ///
    /// [`WalletError::AlreadyEncrypted`] si déjà v2.
    pub fn encrypt_in_place(
        path: impl AsRef<Path>,
        passphrase: &[u8],
    ) -> Result<Self, WalletError> {
        let path = path.as_ref();
        let kf = Self::load(path)?;
        if kf.version != 1 {
            return Err(WalletError::AlreadyEncrypted);
        }
        let kf2 = Self {
            version: 2,
            seed_hex: kf.seed_hex.clone(),
            address_hex: kf.address_hex.clone(),
            created_at: kf.created_at,
            evm_secret_hex: kf.evm_secret_hex.clone(),
            kdf_params: Some(KdfParams::default()),
        };
        kf2.write_v2(path, passphrase)?;
        Ok(kf2)
    }

    /// Déchiffre un keyfile v2 (en place) et retourne le KeyFile v1.
    ///
    /// ⚠️ **Déconseillé** : écrit la seed en clair. À réserver aux
    /// migrations exceptionnelles.
    pub fn decrypt_in_place(
        path: impl AsRef<Path>,
        passphrase: &[u8],
    ) -> Result<Self, WalletError> {
        let path = path.as_ref();
        let kf = Self::load_encrypted(path, passphrase)?;
        let kf1 = Self {
            version: 1,
            seed_hex: kf.seed_hex.clone(),
            address_hex: kf.address_hex.clone(),
            created_at: kf.created_at,
            evm_secret_hex: kf.evm_secret_hex.clone(),
            kdf_params: None,
        };
        kf1.write_v1(path)?;
        Ok(kf1)
    }

    // --- Écriture ----------------------------------------------------------

    fn write_v1(&self, path: &Path) -> Result<(), WalletError> {
        let raw = RawV1 {
            version: 1,
            seed_hex: self.seed_hex.clone(),
            address_hex: self.address_hex.clone(),
            created_at: self.created_at,
            evm_secret_hex: self.evm_secret_hex.clone(),
        };
        write_json_atomic(path, &raw)
    }

    fn write_v2(&self, path: &Path, passphrase: &[u8]) -> Result<(), WalletError> {
        let plain = Plaintext {
            seed_hex: self.seed_hex.clone(),
            evm_secret_hex: self.evm_secret_hex.clone(),
        };
        let mut plaintext_bytes = serde_json::to_vec(&plain)?;
        let params = self.kdf_params.unwrap_or_default();

        // Construire le squelette V2 pour calculer l'AAD, puis chiffrer.
        // Note : on utilise un salt/nonce placeholder pour l'AAD — le
        // déchiffreur reconstruit l'AAD à partir **des mêmes champs**, ce
        // qui rend la comparaison stable.
        let skeleton = RawV2 {
            version: 2,
            created_at: self.created_at,
            address_hex: self.address_hex.clone(),
            kdf: "argon2id".into(),
            kdf_params: RawKdfParams {
                m_cost_kib: params.m_cost_kib,
                t_cost: params.t_cost,
                p_cost: params.p_cost,
                salt_hex: String::new(), // placeholder
            },
            cipher: "chacha20poly1305".into(),
            nonce_hex: String::new(), // placeholder
            ciphertext_hex: String::new(),
        };
        let aad = build_aad(&skeleton);

        let blob = crypto::encrypt(&plaintext_bytes, passphrase, &aad, &params)?;
        plaintext_bytes.zeroize();

        let raw = RawV2 {
            version: 2,
            created_at: self.created_at,
            address_hex: self.address_hex.clone(),
            kdf: "argon2id".into(),
            kdf_params: RawKdfParams {
                m_cost_kib: params.m_cost_kib,
                t_cost: params.t_cost,
                p_cost: params.p_cost,
                salt_hex: hex::encode(blob.salt),
            },
            cipher: "chacha20poly1305".into(),
            nonce_hex: hex::encode(blob.nonce),
            ciphertext_hex: hex::encode(&blob.ciphertext),
        };
        write_json_atomic(path, &raw)
    }
}

// --- Helpers ---------------------------------------------------------------

/// Reconstruit l'AAD à partir des champs non-chiffrés.
///
/// **Important** : l'AAD ne doit **pas** contenir `salt` ni `nonce` — ces
/// champs sont déjà dans le keystore et ne doivent pas être authentifiés
/// par le MAC (sinon un attaquant pourrait modifier le salt et invalider
/// le MAC sans pour autant casser le chiffrement — ce qui rendrait les
/// keystores moins tolérants).
///
/// On authentifie uniquement les **paramètres fonctionnels** (version,
/// KDF params, cipher) qui déterminent la sémantique du ciphertext.
fn build_aad(v2: &RawV2) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(b"SANGO/WALLET/KEYFILE/V2\0");
    aad.extend_from_slice(&v2.version.to_le_bytes());
    aad.extend_from_slice(&v2.created_at.to_le_bytes());
    aad.extend_from_slice(v2.address_hex.as_bytes());
    aad.push(0);
    aad.extend_from_slice(v2.kdf.as_bytes());
    aad.push(0);
    aad.extend_from_slice(&v2.kdf_params.m_cost_kib.to_le_bytes());
    aad.extend_from_slice(&v2.kdf_params.t_cost.to_le_bytes());
    aad.extend_from_slice(&v2.kdf_params.p_cost.to_le_bytes());
    aad.extend_from_slice(v2.cipher.as_bytes());
    aad
}

fn hex_to_fixed<const N: usize>(s: &str, field: &str) -> Result<[u8; N], WalletError> {
    let bytes = hex::decode(s)?;
    if bytes.len() != N {
        return Err(WalletError::InvalidKeyfile(format!(
            "{field}: expected {N} bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), WalletError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(value)?;
    fs::write(&tmp, &bytes)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(&tmp, perms)?;
    }

    fs::rename(&tmp, path)?;
    Ok(())
}

fn random_seed() -> [u8; 32] {
    use rand_core::{OsRng, RngCore};
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

    /// Params KDF réduits pour tests (pas de 64 MiB × 20 tests).
    fn fast_kdf() -> KdfParams {
        KdfParams {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[test]
    fn v1_create_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.json");
        let kf = KeyFile::create(&path).unwrap();
        assert_eq!(kf.version, 1);

        let loaded = KeyFile::load(&path).unwrap();
        assert_eq!(loaded.seed_hex, kf.seed_hex);
        assert_eq!(loaded.address_hex, kf.address_hex);
    }

    #[test]
    fn v2_create_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.json");
        let pass = b"hunter2";

        // On remplace les params par défaut par des params rapides **avant**
        // écriture. Astuce : on écrit d'abord en v1, puis on chiffre in_place.
        let kf1 = KeyFile::create(&path).unwrap();
        std::fs::remove_file(&path).unwrap();

        // On reconstruit un kf avec kdf_params fast et on appelle
        // directement write_v2.
        let kf = KeyFile {
            version: 2,
            seed_hex: kf1.seed_hex.clone(),
            address_hex: kf1.address_hex.clone(),
            created_at: kf1.created_at,
            evm_secret_hex: None,
            kdf_params: Some(fast_kdf()),
        };
        kf.write_v2(&path, pass).unwrap();

        let loaded = KeyFile::load_encrypted(&path, pass).unwrap();
        assert_eq!(loaded.version, 2);
        assert_eq!(loaded.seed_hex, kf.seed_hex);
        assert_eq!(loaded.address_hex, kf.address_hex);
    }

    #[test]
    fn v2_wrong_passphrase_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.json");
        let kf1 = KeyFile::create(&path).unwrap();
        std::fs::remove_file(&path).unwrap();

        let kf = KeyFile {
            version: 2,
            seed_hex: kf1.seed_hex.clone(),
            address_hex: kf1.address_hex.clone(),
            created_at: kf1.created_at,
            evm_secret_hex: None,
            kdf_params: Some(fast_kdf()),
        };
        kf.write_v2(&path, b"good").unwrap();

        let err = KeyFile::load_encrypted(&path, b"bad").unwrap_err();
        assert!(matches!(err, WalletError::InvalidPassphrase));
    }

    #[test]
    fn v1_load_rejects_v2() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.json");
        let kf1 = KeyFile::create(&path).unwrap();
        std::fs::remove_file(&path).unwrap();

        let kf = KeyFile {
            version: 2,
            seed_hex: kf1.seed_hex.clone(),
            address_hex: kf1.address_hex.clone(),
            created_at: kf1.created_at,
            evm_secret_hex: None,
            kdf_params: Some(fast_kdf()),
        };
        kf.write_v2(&path, b"pass").unwrap();

        let err = KeyFile::load(&path).unwrap_err();
        assert!(matches!(err, WalletError::AlreadyEncrypted));
    }

    #[test]
    fn v2_load_rejects_v1() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.json");
        KeyFile::create(&path).unwrap();
        let err = KeyFile::load_encrypted(&path, b"pass").unwrap_err();
        assert!(matches!(err, WalletError::NotEncrypted));
    }

    #[test]
    fn keypair_derives_same_address() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.json");
        let kf = KeyFile::create(&path).unwrap();
        let kp = kf.keypair().unwrap();
        let derived = derive_native_address(&kp.public_key());
        assert_eq!(derived, kf.address().unwrap());
    }

    #[test]
    fn permissions_are_0600() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("wallet.json");
            KeyFile::create(&path).unwrap();
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
