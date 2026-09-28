//! Keyfile V3 : mnemonic BIP-39 chiffrée (Argon2id + ChaCha20-Poly1305).
//!
//! ## Spécification figée
//!
//! ```text
//! AAD       = b"SANGO/WALLET/KEYFILE/V3\0"   (fixe, indépendant du JSON)
//! plaintext = canonical JSON :
//!             { "mnemonic": "...",
//!               "bip39_passphrase_used": false,
//!               "next_account_index": 0 }
//! ```
//!
//! ## Format externe (JSON)
//!
//! ```json
//! {
//!   "version": 3,
//!   "created_at": 1700000000,
//!   "kdf": "argon2id",
//!   "kdf_params": {
//!     "m_cost_kib": 65536, "t_cost": 3, "p_cost": 4,
//!     "salt_hex": "..."
//!   },
//!   "cipher": "chacha20poly1305",
//!   "nonce_hex": "...",
//!   "ciphertext_hex": "..."
//! }
//! ```
//!
//! **Pas de `address_hex` en clair** : les adresses (native + EVM) sont
//! dérivées à la demande depuis la mnemonic déchiffrée. Amélioration de
//! sécurité par rapport à V1/V2.
//!
//! ## Distinction KDF passphrase / BIP-39 passphrase
//!
//! - **KDF passphrase** : mot de passe de chiffrement du keyfile. Jamais
//!   stocké. Nécessaire pour **déchiffrer**.
//! - **BIP-39 passphrase** : 25ᵉ mot de la mnemonic. Jamais stocké
//!   (`bip39_passphrase_used: bool` seulement). Nécessaire pour
//!   **dériver** les clés.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use sango_crypto::bech32m::Network;
use sango_crypto::mnemonic::{Mnemonic, MnemonicLength};
use sango_crypto::NativeKeypair;
use sango_primitives::{EvmAddress, NativeAddress};

use crate::crypto::{self, EncryptedBlob, KdfParams, NONCE_LEN, SALT_LEN};
use crate::error::WalletError;
use crate::evm::EvmKeypair;
use crate::keystore::{hex_to_fixed, write_json_atomic};
use crate::wallet_v3::WalletV3;

/// AAD **fixe** du keyfile V3.
///
/// Indépendante du JSON externe : toute modification est un hard fork
/// du format V3 (à documenter et coordonner).
pub const KEYFILE_V3_AAD: &[u8] = b"SANGO/WALLET/KEYFILE/V3\0";

// --- JSON externe ----------------------------------------------------------

#[derive(Debug, Deserialize, Serialize)]
struct RawV3 {
    version: u32,
    created_at: u64,
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

/// Plaintext chiffré (JSON canonique).
///
/// **Ne pas dériver `Debug`** : la mnemonic apparaîtrait en clair dans
/// les logs.
#[derive(Serialize, Deserialize)]
struct PlaintextV3 {
    mnemonic: String,
    bip39_passphrase_used: bool,
    next_account_index: u32,
}

// --- KeyFileV3 -------------------------------------------------------------

/// Keyfile V3 en mémoire (mnemonic déchiffrée).
///
/// Les buffers contenant la mnemonic sont effacés au `Drop`.
pub struct KeyFileV3 {
    /// Timestamp Unix de création.
    pub created_at: u64,
    /// Paramètres Argon2id utilisés (pour réécriture éventuelle).
    pub kdf_params: KdfParams,
    /// Prochain index d'account (réservé, `0` en V1).
    pub next_account_index: u32,
    /// Vrai si le keyfile a été créé avec une passphrase BIP-39 non-vide.
    ///
    /// **Flag persisté** : restitué tel quel au chargement, indépendamment
    /// de la passphrase effectivement fournie par le caller. Si `true`,
    /// le caller **doit** fournir la passphrase BIP-39 pour dériver les
    /// bonnes clés (elle n'est jamais stockée).
    bip39_passphrase_used: bool,
    /// Wallet V3 (mnemonic + passphrase BIP-39 optionnelle).
    wallet: WalletV3,
}

impl std::fmt::Debug for KeyFileV3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyFileV3")
            .field("created_at", &self.created_at)
            .field("kdf_params", &self.kdf_params)
            .field("next_account_index", &self.next_account_index)
            .field("bip39_passphrase_used", &self.bip39_passphrase_used)
            .field("wallet", &"<redacted>")
            .finish()
    }
}

impl KeyFileV3 {
    /// Génère un nouveau wallet V3 (mnemonic aléatoire) et écrit le
    /// keyfile chiffré.
    ///
    /// ## Paramètres
    ///
    /// - `kdf_passphrase` : mot de passe de chiffrement du keyfile.
    /// - `length` : 12 ou 24 mots.
    pub fn create(
        path: impl AsRef<Path>,
        length: MnemonicLength,
        kdf_passphrase: &[u8],
    ) -> Result<Self, WalletError> {
        let path = path.as_ref();
        if path.exists() {
            return Err(WalletError::KeyfileExists(path.display().to_string()));
        }
        if kdf_passphrase.is_empty() {
            return Err(WalletError::EmptyPassphrase);
        }
        let wallet = WalletV3::generate(length)?;
        let kf = Self {
            created_at: now_unix(),
            kdf_params: KdfParams::default(),
            next_account_index: 0,
            bip39_passphrase_used: false,
            wallet,
        };
        kf.write(path, kdf_passphrase)?;
        Ok(kf)
    }

    /// Importe un wallet V3 depuis une mnemonic fournie.
    pub fn import(
        path: impl AsRef<Path>,
        mnemonic: &str,
        bip39_passphrase: Option<String>,
        kdf_passphrase: &[u8],
    ) -> Result<Self, WalletError> {
        let path = path.as_ref();
        if path.exists() {
            return Err(WalletError::KeyfileExists(path.display().to_string()));
        }
        if kdf_passphrase.is_empty() {
            return Err(WalletError::EmptyPassphrase);
        }
        let wallet = WalletV3::from_mnemonic_str(mnemonic, bip39_passphrase)?;
        let bip39_passphrase_used = wallet.passphrase_used();
        let kf = Self {
            created_at: now_unix(),
            kdf_params: KdfParams::default(),
            next_account_index: 0,
            bip39_passphrase_used,
            wallet,
        };
        kf.write(path, kdf_passphrase)?;
        Ok(kf)
    }

    /// Charge un keyfile V3 chiffré.
    ///
    /// ## Paramètres
    ///
    /// - `kdf_passphrase` : mot de passe de chiffrement du keyfile.
    /// - `bip39_passphrase` : si le fichier indique
    ///   `bip39_passphrase_used == true`, cette valeur **doit** être
    ///   fournie pour dériver les bonnes clés. Le format V3 **ne stocke
    ///   pas** la passphrase BIP-39.
    pub fn load_encrypted(
        path: impl AsRef<Path>,
        kdf_passphrase: &[u8],
        bip39_passphrase: Option<String>,
    ) -> Result<Self, WalletError> {
        let path = path.as_ref();
        let bytes = fs::read(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                WalletError::KeyfileNotFound(path.display().to_string())
            } else {
                WalletError::Io(e)
            }
        })?;
        let raw: RawV3 = serde_json::from_slice(&bytes)?;

        if raw.version != 3 {
            return Err(WalletError::InvalidKeyfile(format!(
                "expected V3, got version {}",
                raw.version
            )));
        }
        if raw.kdf != "argon2id" {
            return Err(WalletError::InvalidKeyfile(format!(
                "unsupported kdf: {}",
                raw.kdf
            )));
        }
        if raw.cipher != "chacha20poly1305" {
            return Err(WalletError::InvalidKeyfile(format!(
                "unsupported cipher: {}",
                raw.cipher
            )));
        }

        let salt = hex_to_fixed::<SALT_LEN>(&raw.kdf_params.salt_hex, "salt")?;
        let nonce = hex_to_fixed::<NONCE_LEN>(&raw.nonce_hex, "nonce")?;
        let ciphertext = hex::decode(&raw.ciphertext_hex)?;

        let params = KdfParams {
            m_cost_kib: raw.kdf_params.m_cost_kib,
            t_cost: raw.kdf_params.t_cost,
            p_cost: raw.kdf_params.p_cost,
        };

        let blob = EncryptedBlob {
            salt,
            nonce,
            ciphertext,
        };

        let mut plaintext_bytes = zeroize::Zeroizing::new(crypto::decrypt(
            &blob,
            kdf_passphrase,
            KEYFILE_V3_AAD,
            &params,
        )?);

        let mut plain: PlaintextV3 = serde_json::from_slice(&plaintext_bytes)
            .map_err(|e| WalletError::InvalidKeyfile(format!("plaintext: {e}")))?;
        // Effacer le buffer de déchiffrement dès qu'il n'est plus utile.
        plaintext_bytes.zeroize();

        let mnemonic = Mnemonic::parse(&plain.mnemonic)
            .map_err(|e| WalletError::InvalidKeyfile(format!("stored mnemonic invalid: {e}")))?;
        // Effacer la copie locale (le contenu est repris par `Mnemonic`).
        plain.mnemonic.zeroize();

        let wallet = WalletV3::from_mnemonic(mnemonic, bip39_passphrase);
        // Le flag est lu **depuis le plaintext**, pas dérivé du wallet :
        // il doit refléter l'état au moment de la création, même si le
        // caller ne fournit pas la passphrase BIP-39 au chargement.
        let bip39_passphrase_used = plain.bip39_passphrase_used;

        Ok(Self {
            created_at: raw.created_at,
            kdf_params: params,
            next_account_index: plain.next_account_index,
            bip39_passphrase_used,
            wallet,
        })
    }

    /// Écrit le keyfile chiffré (écriture atomique `0600`).
    pub fn write(&self, path: impl AsRef<Path>, kdf_passphrase: &[u8]) -> Result<(), WalletError> {
        if kdf_passphrase.is_empty() {
            return Err(WalletError::EmptyPassphrase);
        }

        // Sérialiser le plaintext en JSON canonique compact.
        let plain = PlaintextV3 {
            mnemonic: self.wallet.mnemonic_owned().as_str().to_string(),
            bip39_passphrase_used: self.wallet.passphrase_used(),
            next_account_index: self.next_account_index,
        };
        let mut plaintext_bytes = zeroize::Zeroizing::new(serde_json::to_vec(&plain)?);

        let blob = crypto::encrypt(
            &plaintext_bytes,
            kdf_passphrase,
            KEYFILE_V3_AAD,
            &self.kdf_params,
        )?;
        plaintext_bytes.zeroize();

        let raw = RawV3 {
            version: 3,
            created_at: self.created_at,
            kdf: "argon2id".into(),
            kdf_params: RawKdfParams {
                m_cost_kib: self.kdf_params.m_cost_kib,
                t_cost: self.kdf_params.t_cost,
                p_cost: self.kdf_params.p_cost,
                salt_hex: hex::encode(blob.salt),
            },
            cipher: "chacha20poly1305".into(),
            nonce_hex: hex::encode(blob.nonce),
            ciphertext_hex: hex::encode(&blob.ciphertext),
        };
        write_json_atomic(path.as_ref(), &raw)
    }

    /// Retourne une copie effaçable de la mnemonic.
    ///
    /// Usage : commande CLI `export-mnemonic`, tests.
    #[must_use]
    pub fn mnemonic_owned(&self) -> zeroize::Zeroizing<String> {
        self.wallet.mnemonic_owned()
    }

    /// Vrai si une passphrase BIP-39 non-vide est utilisée.
    ///
    /// **Flag persisté** : reflète l'état au moment de la création,
    /// pas la passphrase effectivement fournie au chargement. Si `true`,
    /// l'appelant doit fournir la passphrase BIP-39 pour dériver les
    /// bonnes clés.
    #[must_use]
    pub fn bip39_passphrase_used(&self) -> bool {
        self.bip39_passphrase_used
    }

    /// Dérive le keypair natif Sango à l'index donné.
    ///
    /// Utilise [`Network::Devnet`] en interne (devnet et testnet partagent
    /// le coin type `100001`). Le `Network` passé au CLI ne sert qu'à
    /// l'affichage bech32m.
    pub fn sango_keypair(&self, account_index: u32) -> Result<NativeKeypair, WalletError> {
        self.wallet.sango_keypair(Network::Devnet, account_index)
    }

    /// Dérive le keypair EVM à l'index donné.
    pub fn evm_keypair(&self, account_index: u32) -> Result<EvmKeypair, WalletError> {
        self.wallet.evm_keypair(account_index)
    }

    /// Adresse native à l'index donné.
    pub fn address(&self, account_index: u32) -> Result<NativeAddress, WalletError> {
        let kp = self.sango_keypair(account_index)?;
        Ok(sango_crypto::derive_native_address(&kp.public_key()))
    }

    /// Adresse EVM à l'index donné.
    pub fn evm_address(&self, account_index: u32) -> Result<EvmAddress, WalletError> {
        Ok(self.evm_keypair(account_index)?.address())
    }
}

impl Drop for KeyFileV3 {
    fn drop(&mut self) {
        // `WalletV3` gère son propre effacement (`Zeroizing`).
        // Rien d'autre à faire ici, mais on garde le `Drop` explicite
        // pour documenter l'intention.
    }
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

    /// Paramètres Argon2id **rapides** pour les tests (pas de 64 MiB).
    fn fast_kdf() -> KdfParams {
        KdfParams {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        }
    }

    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /// Crée un KeyFileV3 en mémoire avec paramètres rapides et l'écrit.
    fn write_v3(path: &Path, kdf_pass: &[u8]) {
        let kf = KeyFileV3 {
            created_at: 1_700_000_000,
            kdf_params: fast_kdf(),
            next_account_index: 0,
            bip39_passphrase_used: false,
            wallet: WalletV3::from_mnemonic_str(TEST_MNEMONIC, None).unwrap(),
        };
        kf.write(path, kdf_pass).unwrap();
    }

    #[test]
    fn v3_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.json");
        let pass = b"hunter2";
        write_v3(&path, pass);

        let kf = KeyFileV3::load_encrypted(&path, pass, None).unwrap();
        assert_eq!(kf.mnemonic_owned().as_str(), TEST_MNEMONIC);
        assert!(!kf.bip39_passphrase_used());
        assert_eq!(kf.next_account_index, 0);
        assert_eq!(kf.created_at, 1_700_000_000);
    }

    #[test]
    fn v3_wrong_passphrase_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.json");
        write_v3(&path, b"good");
        let err = KeyFileV3::load_encrypted(&path, b"bad", None).unwrap_err();
        assert!(matches!(err, WalletError::InvalidPassphrase));
    }

    #[test]
    fn v3_created_at_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.json");
        write_v3(&path, b"pass");
        let kf = KeyFileV3::load_encrypted(&path, b"pass", None).unwrap();
        assert_eq!(kf.created_at, 1_700_000_000);
    }

    #[test]
    fn v3_permissions_are_0600() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("wallet.json");
            write_v3(&path, b"pass");
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn v3_addresses_are_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.json");
        write_v3(&path, b"pass");
        let kf = KeyFileV3::load_encrypted(&path, b"pass", None).unwrap();

        let n1 = kf.address(0).unwrap();
        let n2 = kf.address(0).unwrap();
        assert_eq!(n1, n2);

        let e1 = kf.evm_address(0).unwrap();
        let e2 = kf.evm_address(0).unwrap();
        assert_eq!(e1, e2);

        // Native ≠ EVM.
        assert_ne!(n1.as_bytes(), e1.as_bytes());
    }

    #[test]
    fn v3_import_preserves_mnemonic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.json");
        let kf = KeyFileV3::import(&path, TEST_MNEMONIC, None, b"pass").unwrap();
        assert_eq!(kf.mnemonic_owned().as_str(), TEST_MNEMONIC);

        let kf2 = KeyFileV3::load_encrypted(&path, b"pass", None).unwrap();
        assert_eq!(kf2.mnemonic_owned().as_str(), TEST_MNEMONIC);
    }

    #[test]
    fn v3_bip39_passphrase_used_flag_is_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.json");
        let _ = KeyFileV3::import(&path, TEST_MNEMONIC, Some("secret".into()), b"pass").unwrap();

        let kf = KeyFileV3::load_encrypted(&path, b"pass", Some("secret".into())).unwrap();
        assert!(kf.bip39_passphrase_used());

        // Sans la passphrase BIP-39, les adresses diffèrent.
        let kf_no_pass = KeyFileV3::load_encrypted(&path, b"pass", None).unwrap();
        assert!(kf_no_pass.bip39_passphrase_used());
        assert_ne!(
            kf.address(0).unwrap().as_bytes(),
            kf_no_pass.address(0).unwrap().as_bytes()
        );
    }

    #[test]
    fn v3_rejects_wrong_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.json");
        write_v3(&path, b"pass");
        // Modifier la version dans le JSON.
        let mut raw: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        raw["version"] = serde_json::json!(2);
        fs::write(&path, serde_json::to_vec(&raw).unwrap()).unwrap();

        let err = KeyFileV3::load_encrypted(&path, b"pass", None).unwrap_err();
        assert!(matches!(err, WalletError::InvalidKeyfile(_)));
    }

    #[test]
    fn v3_empty_kdf_passphrase_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.json");
        let err = KeyFileV3::create(&path, MnemonicLength::Words24, b"").unwrap_err();
        assert!(matches!(err, WalletError::EmptyPassphrase));
    }

    #[test]
    fn v3_debug_does_not_leak_mnemonic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.json");
        write_v3(&path, b"pass");
        let kf = KeyFileV3::load_encrypted(&path, b"pass", None).unwrap();
        let s = format!("{kf:?}");
        assert!(s.contains("redacted"));
        assert!(!s.contains("abandon"));
    }
}
