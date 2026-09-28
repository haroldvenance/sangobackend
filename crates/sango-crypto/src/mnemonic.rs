//! Mnemonic BIP-39 (anglais uniquement en V1).
//!
//! ## Périmètre
//!
//! Ce module implémente la **couche BIP-39** du wallet multi-chain :
//! génération, validation, dérivation du seed. La dérivation HD
//! (BIP-32 / SLIP-0010) vit dans un module séparé (W3).
//!
//! ## Langue
//!
//! **Anglais uniquement** en V1. Une mnemonic française ne se restaure
//! pas dans MetaMask/Phantom/Ledger, on ne fait pas d'exception.
//!
//! ## Passphrase BIP-39 (25ᵉ mot)
//!
//! Supportée dès maintenant dans l'API ([`Mnemonic::to_seed`]), même si
//! l'UI frontend peut choisir de ne pas l'exposer. Rétro-ajouter une
//! passphrase après coup est impossible sans casser les dérivations
//! existantes.
//!
//! ## Normalisation NFKD
//!
//! Le parseur et le calcul de seed reposent sur la normalisation NFKD
//! implémentée par `bip39` (conforme au standard). On ne réimplémente
//! pas de normalisation ad hoc.
//!
//! ## Longueurs supportées
//!
//! 12 ou 24 mots. Les longueurs 15/18/21 (valides BIP-39) sont
//! **refusées** en V1 pour réduire la surface d'usage et forcer un
//! choix clair côté UI.

use bip39::{Language, Mnemonic as Bip39Mnemonic};
use rand_core::OsRng;
use thiserror::Error;
use zeroize::Zeroizing;

/// Nombre de mots d'une mnemonic Sango V1.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum MnemonicLength {
    /// 128 bits d'entropie (12 mots).
    Words12,
    /// 256 bits d'entropie (24 mots).
    Words24,
}

impl MnemonicLength {
    /// Nombre de mots correspondant.
    #[must_use]
    pub const fn word_count(self) -> usize {
        match self {
            MnemonicLength::Words12 => 12,
            MnemonicLength::Words24 => 24,
        }
    }
}

/// Erreur produite par la manipulation d'une mnemonic.
#[derive(Debug, Error)]
pub enum MnemonicError {
    /// Mnemonic invalide (mots inconnus, checksum incorrect, longueur
    /// non supportée).
    #[error("invalid mnemonic: {0}")]
    Invalid(String),
    /// Échec de génération (CSPRNG de l'OS indisponible).
    #[error("mnemonic generation failed: {0}")]
    Generation(String),
}

/// Mnemonic BIP-39 anglaise.
///
/// Le contenu est effacé de la mémoire au Drop (`Zeroizing`).
pub struct Mnemonic {
    inner: Zeroizing<String>,
}

impl Mnemonic {
    /// Génère une nouvelle mnemonic via le CSPRNG de l'OS.
    ///
    /// # Erreurs
    ///
    /// [`MnemonicError::Generation`] si l'entropie de l'OS est
    /// indisponible.
    pub fn generate(length: MnemonicLength) -> Result<Self, MnemonicError> {
        let m = Bip39Mnemonic::generate_in_with(&mut OsRng, Language::English, length.word_count())
            .map_err(|e| MnemonicError::Generation(e.to_string()))?;
        Ok(Self {
            inner: Zeroizing::new(m.to_string()),
        })
    }

    /// Parse et valide une mnemonic BIP-39 anglaise.
    ///
    /// La normalisation NFKD et la vérification du checksum sont
    /// déléguées à `bip39`. Seules les longueurs **12 ou 24 mots**
    /// sont acceptées ; les longueurs 15/18/21 sont refusées
    /// explicitement.
    ///
    /// # Erreurs
    ///
    /// [`MnemonicError::Invalid`] si la mnemonic est mal formée, a un
    /// checksum incorrect, contient un mot inconnu, ou a un nombre de
    /// mots non supporté.
    pub fn parse(s: &str) -> Result<Self, MnemonicError> {
        let word_count = s.split_whitespace().count();
        if word_count != 12 && word_count != 24 {
            return Err(MnemonicError::Invalid(format!(
                "unsupported word count: {word_count} (expected 12 or 24)"
            )));
        }
        let m = Bip39Mnemonic::parse_in(Language::English, s)
            .map_err(|e| MnemonicError::Invalid(e.to_string()))?;
        Ok(Self {
            inner: Zeroizing::new(m.to_string()),
        })
    }

    /// Mots de la mnemonic, dans l'ordre.
    #[must_use]
    pub fn words(&self) -> Vec<&str> {
        self.inner.split_whitespace().collect()
    }

    /// Nombre de mots.
    #[must_use]
    pub fn word_count(&self) -> usize {
        self.inner.split_whitespace().count()
    }

    /// Dérive le seed BIP-39 (64 bytes) avec passphrase optionnelle.
    ///
    /// `passphrase = None` équivaut à `passphrase = Some("")`.
    ///
    /// La normalisation NFKD de la mnemonic et de la passphrase est
    /// déléguée à `bip39`.
    ///
    /// Le seed retourné est effacé de la mémoire au Drop.
    #[must_use]
    pub fn to_seed(&self, passphrase: Option<&str>) -> Zeroizing<[u8; 64]> {
        let bip = Bip39Mnemonic::parse_in(Language::English, self.inner.as_str())
            .expect("internal mnemonic is always valid");
        let pass = passphrase.unwrap_or("");
        Zeroizing::new(bip.to_seed(pass))
    }

    /// Accès brut à la mnemonic (usage interne pour chiffrement V3).
    ///
    /// **`pub(crate)`** : réservé au code interne de `sango-crypto`.
    /// Pour un accès depuis `sango-wallet` (W4), une API dédiée sera
    /// ajoutée avec audit des call-sites, plutôt que d'exposer la
    /// mnemonic en clair publiquement.
    ///
    /// **Pourquoi `#[allow(dead_code)]`** : cette méthode est
    /// introduite en W2 mais son premier appelant réel vit en W4
    /// (chiffrement du keyfile V3). Sans l'annotation, `clippy
    /// -D warnings` refuse la compilation. À retirer en W4 dès que
    /// le chiffrement consomme la méthode.
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn as_str(&self) -> &str {
        self.inner.as_str()
    }
}

impl std::fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mnemonic")
            .field("words", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Génération --------------------------------------------------------

    #[test]
    fn generate_12_words() {
        let m = Mnemonic::generate(MnemonicLength::Words12).unwrap();
        assert_eq!(m.word_count(), 12);
    }

    #[test]
    fn generate_24_words() {
        let m = Mnemonic::generate(MnemonicLength::Words24).unwrap();
        assert_eq!(m.word_count(), 24);
    }

    #[test]
    fn generate_is_random() {
        let a = Mnemonic::generate(MnemonicLength::Words12).unwrap();
        let b = Mnemonic::generate(MnemonicLength::Words12).unwrap();
        assert_ne!(a.as_str(), b.as_str());
    }

    // --- Parsing -----------------------------------------------------------

    #[test]
    fn parse_roundtrip() {
        let m = Mnemonic::generate(MnemonicLength::Words12).unwrap();
        let s = m.as_str().to_string();
        let m2 = Mnemonic::parse(&s).unwrap();
        assert_eq!(m.as_str(), m2.as_str());
    }

    #[test]
    fn parse_extra_whitespace_is_tolerated() {
        let m = Mnemonic::generate(MnemonicLength::Words12).unwrap();
        let s = format!("  {}  ", m.as_str());
        let m2 = Mnemonic::parse(&s).unwrap();
        assert_eq!(m.as_str(), m2.as_str());
    }

    #[test]
    fn parse_rejects_15_words() {
        // 15 mots = longueur BIP-39 valide, refusée en V1.
        let s = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let err = Mnemonic::parse(s).unwrap_err();
        match err {
            MnemonicError::Invalid(msg) => assert!(msg.contains("15"), "got: {msg}"),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_18_words() {
        let s = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        let err = Mnemonic::parse(s).unwrap_err();
        match err {
            MnemonicError::Invalid(msg) => assert!(msg.contains("18"), "got: {msg}"),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_21_words() {
        let s = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        let err = Mnemonic::parse(s).unwrap_err();
        match err {
            MnemonicError::Invalid(msg) => assert!(msg.contains("21"), "got: {msg}"),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_invalid_checksum() {
        // "abandon ... about" est valide. On remplace le dernier mot
        // par un autre mot BIP-39 → le checksum ne correspond plus.
        let s = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zoo";
        let err = Mnemonic::parse(s).unwrap_err();
        assert!(matches!(err, MnemonicError::Invalid(_)));
    }

    #[test]
    fn parse_rejects_unknown_word() {
        let s = "notaword abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let err = Mnemonic::parse(s).unwrap_err();
        assert!(matches!(err, MnemonicError::Invalid(_)));
    }

    #[test]
    fn parse_rejects_empty() {
        assert!(Mnemonic::parse("").is_err());
    }

    // --- Dérivation seed ---------------------------------------------------

    #[test]
    fn passphrase_none_equals_empty_string() {
        let m = Mnemonic::generate(MnemonicLength::Words12).unwrap();
        let a = m.to_seed(None);
        let b = m.to_seed(Some(""));
        assert_eq!(&a[..], &b[..]);
    }

    #[test]
    fn passphrase_changes_seed() {
        let m = Mnemonic::generate(MnemonicLength::Words12).unwrap();
        let a = m.to_seed(Some("hunter2"));
        let b = m.to_seed(Some("hunter3"));
        assert_ne!(&a[..], &b[..]);
    }

    #[test]
    fn seed_is_64_bytes() {
        let m = Mnemonic::generate(MnemonicLength::Words12).unwrap();
        let seed = m.to_seed(None);
        assert_eq!(seed.len(), 64);
    }

    // --- Sécurité ----------------------------------------------------------

    #[test]
    fn debug_does_not_leak_mnemonic() {
        let m = Mnemonic::generate(MnemonicLength::Words12).unwrap();
        let s = format!("{m:?}");
        assert!(s.contains("redacted"));
        for w in m.words() {
            assert!(!s.contains(w), "Debug leaked word: {w}");
        }
    }

    #[test]
    fn word_count_matches_length() {
        assert_eq!(MnemonicLength::Words12.word_count(), 12);
        assert_eq!(MnemonicLength::Words24.word_count(), 24);
    }
}
