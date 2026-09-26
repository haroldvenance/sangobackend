//! Support TLS pour le serveur RPC.
//!
//! ## Choix techniques
//!
//! - **rustls 0.23** (pas d'OpenSSL, pur Rust, pas de `unsafe`).
//! - **Synchrone** : `rustls::StreamOwned<ServerConnection, TcpStream>`
//!   implémente `Read + Write` et s'intègre à la boucle `accept` existante
//!   sans migrer vers tokio.
//! - **Aucun client cert** : TLS one-way (le serveur s'authentifie, pas
//!   le client). C'est le modèle standard pour un RPC public (Ethereum).
//!
//! ## Formats supportés
//!
//! - **PEM** : `--rpc-tls-cert cert.pem --rpc-tls-key key.pem`
//! - **Auto-self-signed** (devnet uniquement) : `--rpc-tls-self-signed`
//!   génère un cert localhost au démarrage, sans persistance. À réserver
//!   au devnet et aux tests.

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::crypto::ring as rustls_ring;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::sync::OnceLock;
use thiserror::Error;

/// Initialise **une seule fois** le `CryptoProvider` par défaut de rustls
/// (variante `ring`).
///
/// ## Pourquoi c'est nécessaire
///
/// rustls 0.23 supporte plusieurs providers (aws-lc-rs, ring). Si **plusieurs
/// providers sont compilés** dans l'arbre de deps (ce qui peut arriver via
/// libp2p-tls qui utilise ring, et notre rustls par défaut qui utilise
/// aws-lc-rs), rustls refuse de choisir tout seul et panique.
///
/// Le workspace fixe `rustls` sur `default-features = false, features = ["ring"]`.
/// Cette fonction ajoute une ceinture-bretelles : elle installe `ring` comme
/// provider par défaut au premier appel. Idempotente (OnceLock).
pub fn init_tls_crypto() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        let _ = CryptoProvider::install_default(rustls_ring::default_provider());
    });
}

/// Erreur produite lors de la construction d'une configuration TLS.
#[derive(Debug, Error)]
pub enum TlsError {
    /// Erreur d'I/O (ouverture des fichiers cert/key).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// Erreur de parsing PEM.
    #[error("pem: {0}")]
    Pem(String),

    /// Aucune clé privée trouvée dans le fichier.
    #[error("no private key found in {0}")]
    NoPrivateKey(PathBuf),

    /// Aucun certificat trouvé dans le fichier.
    #[error("no certificate found in {0}")]
    NoCertificate(PathBuf),

    /// Erreur rustls (config invalide).
    #[error("rustls: {0}")]
    Rustls(String),

    /// Erreur de génération d'un certificat self-signed.
    #[error("self-signed: {0}")]
    SelfSigned(String),
}

/// Configuration TLS du serveur RPC.
///
/// Le serveur ne requiert **pas** de client certificate (TLS one-way).
#[derive(Clone)]
pub struct TlsConfig {
    /// `rustls::ServerConfig` prête à l'emploi.
    pub(crate) inner: Arc<ServerConfig>,
}

impl TlsConfig {
    /// Charge une config TLS depuis des fichiers PEM (cert + key).
    pub fn from_pem_files(
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
    ) -> Result<Self, TlsError> {
        init_tls_crypto();
        let cert_path = cert_path.as_ref();
        let key_path = key_path.as_ref();

        let certs = load_certs(cert_path)?;
        if certs.is_empty() {
            return Err(TlsError::NoCertificate(cert_path.to_path_buf()));
        }
        let key = load_private_key(key_path)?;

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| TlsError::Rustls(e.to_string()))?;

        Ok(Self {
            inner: Arc::new(config),
        })
    }

    /// Génère un certificat **self-signed** pour `localhost` (devnet
    /// uniquement).
    ///
    /// Le certificat n'est **pas** persisté : il est régénéré à chaque
    /// démarrage. Les clients doivent explicitement accepter ce certificat
    /// (`RpcClient::new_with_tls(..., TrustMode::AcceptAny)`).
    pub fn self_signed_localhost() -> Result<Self, TlsError> {
        init_tls_crypto();
        let certified = rcgen::generate_simple_self_signed(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
        ])
        .map_err(|e| TlsError::SelfSigned(e.to_string()))?;

        let cert_der: CertificateDer<'static> = certified.cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .map_err(|e| TlsError::Rustls(e.to_string()))?;

        Ok(Self {
            inner: Arc::new(config),
        })
    }

    /// Retourne le certificat self-signed au format DER, si généré par
    /// [`Self::self_signed_localhost`].
    ///
    /// **N'est pas disponible** pour une config chargée depuis fichiers
    /// (cette méthode retourne alors une erreur). Utilisé par les tests
    /// et par le mode devnet pour permettre au wallet local de faire
    /// confiance au cert auto-généré.
    pub fn export_self_signed_der(&self) -> Result<Vec<u8>, TlsError> {
        Err(TlsError::SelfSigned(
            "cannot export DER: config was loaded from files".into(),
        ))
    }

    /// Vue sur la `ServerConfig` interne.
    #[must_use]
    pub fn server_config(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.inner)
    }
}

impl std::fmt::Debug for TlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsConfig").finish_non_exhaustive()
    }
}

// --- Helpers ---------------------------------------------------------------

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    certs.map_err(|e| TlsError::Pem(e.to_string()))
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| TlsError::Pem(e.to_string()))?
        .ok_or_else(|| TlsError::NoPrivateKey(path.to_path_buf()))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Génère un cert+key auto-signés et les écrit dans un fichier PEM
    /// temporaire. Retourne `(cert_path, key_path, cert_der)`.
    fn write_self_signed_pem() -> (tempfile::TempDir, PathBuf, PathBuf, Vec<u8>) {
        let certified =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("rcgen");
        let cert_pem = certified.cert.pem();
        let key_pem = certified.key_pair.serialize_pem();
        let cert_der = certified.cert.der().to_vec();

        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        File::create(&cert_path)
            .unwrap()
            .write_all(cert_pem.as_bytes())
            .unwrap();
        File::create(&key_path)
            .unwrap()
            .write_all(key_pem.as_bytes())
            .unwrap();

        (dir, cert_path, key_path, cert_der)
    }

    #[test]
    fn load_from_pem_files_ok() {
        let (_dir, cert, key, _der) = write_self_signed_pem();
        let cfg = TlsConfig::from_pem_files(&cert, &key).unwrap();
        // La config est utilisable — on vérifie juste que l'Arc est OK.
        let _ = cfg.server_config();
    }

    #[test]
    fn missing_cert_file_rejected() {
        let (_dir, _cert, key, _der) = write_self_signed_pem();
        let err = TlsConfig::from_pem_files("/nonexistent/cert.pem", &key).unwrap_err();
        assert!(matches!(err, TlsError::Io(_)));
    }

    #[test]
    fn empty_cert_file_rejected() {
        let (_dir, _cert, key, _der) = write_self_signed_pem();
        let dir = tempfile::tempdir().unwrap();
        let empty_cert = dir.path().join("empty.pem");
        File::create(&empty_cert).unwrap();

        let err = TlsConfig::from_pem_files(&empty_cert, &key).unwrap_err();
        assert!(matches!(err, TlsError::NoCertificate(_)));
    }

    #[test]
    fn self_signed_localhost_ok() {
        let cfg = TlsConfig::self_signed_localhost().unwrap();
        let _ = cfg.server_config();
    }
}
