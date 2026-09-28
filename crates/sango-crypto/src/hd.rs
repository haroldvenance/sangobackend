//! Dérivation HD (BIP-32 + SLIP-0010).
//!
//! ## Périmètre
//!
//! Ce module fournit la **couche HD** du wallet multi-chain :
//!
//! - **BIP-32** : dérivation secp256k1 (BTC, EVM, ...).
//! - **SLIP-0010** : dérivation Ed25519 (SOL, Sango natif, ...).
//! - **`DerivationPath`** : parsing strict de `m/44'/COIN'/0'/0'/0'`.
//!
//! ## Choix d'implémentation : local, pas de crate `bip32`/`slip10`
//!
//! Conformément à la revue W1 (D2) et W3, on **n'utilise pas** les
//! crates `bip32` ni `slip10` :
//!
//! - La dérivation BIP-32 privée est ~80 lignes avec `hmac` + `sha2` +
//!   `k256`. La crate `bip32` standalone utilise `secp256k1` (bitcoin C)
//!   par défaut, pas `k256`, et son API est mouvante.
//! - SLIP-0010 Ed25519 est encore plus simple (hardened uniquement),
//!   implémentable en ~30 lignes.
//!
//! Résultat : contrôle complet du comportement, aucune ambiguïté sur
//! les edge cases, interop TS ↔ Rust triviale (même algorithme).
//!
//! ## Cas d'erreur BIP-32
//!
//! La spécification BIP-32 prévoit deux cas dégénérés :
//!
//! 1. `parse256(IL) >= n` : la clé dérivée est invalide.
//! 2. `ki == 0` : la clé enfant est nulle.
//!
//! Dans les deux cas, la spec recommande de « proceed with the next value
//! for i ». La probabilité cumulée est `< 2^-127`, donc on **erreur** au
//! lieu de retenter. Documenté et testable.
//!
//! ## Sécurité
//!
//! - La clé privée est stockée dans un `Zeroizing<[u8; 32]>` (effacé au
//!   Drop).
//! - Le `chain_code` est stocké en clair mais **sensible** : combiné à
//!   la clé privée, il permet de dériver tous les enfants.
//! - Le `Debug` de `XPrvSecp256k1` et `XPrvEd25519` **redacte** la clé
//!   privée et le chain code.
//! - L'accès à la clé privée passe par `private_key()` (documenté comme
//!   sensible), ou — préférable — par `to_native_keypair()` /
//!   `to_signing_key()` qui encapsulent l'usage.

use std::fmt;

use hmac::{Hmac, Mac};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{FieldBytes, ProjectivePoint, Scalar};
use sha2::Sha512;
use thiserror::Error;
use zeroize::Zeroizing;

use sango_primitives::PublicKey;

use crate::ed25519::NativeKeypair;

type HmacSha512 = Hmac<Sha512>;

// --- Errors ----------------------------------------------------------------

/// Erreur de dérivation HD.
#[derive(Debug, Error)]
pub enum HdError {
    /// Chemin de dérivation invalide (syntaxe, index hors bornes).
    #[error("invalid derivation path: {0}")]
    InvalidPath(String),

    /// SLIP-0010 exige une dérivation hardened pour Ed25519.
    #[error("Ed25519 requires hardened derivation at index {index}")]
    Ed25519RequiresHardened {
        /// Index fautif.
        index: u32,
    },

    /// BIP-32 : clé dérivée invalide (`IL >= n` ou `ki == 0`).
    ///
    /// Cas purement théorique (probabilité < 2^-127). Documenté.
    #[error("invalid child key at index {index}")]
    InvalidChildKey {
        /// Index fautif.
        index: u32,
    },
}

// --- ChildIndex ------------------------------------------------------------

/// Index de dérivation HD.
///
/// ## Convention
///
/// La valeur stockée est **logique** : toujours dans `[0, 2^31)`.
/// Le bit hardened est ajouté **uniquement** lors de la sérialisation
/// BIP-32 (`value | 0x8000_0000`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ChildIndex {
    /// Index non-hardened (`/0`, `/1`, ...).
    Normal(u32),
    /// Index hardened (`/0'`, `/1'`, ...).
    Hardened(u32),
}

impl ChildIndex {
    /// Valeur logique, toujours `< 2^31`.
    #[must_use]
    pub const fn value(self) -> u32 {
        match self {
            ChildIndex::Normal(v) | ChildIndex::Hardened(v) => v,
        }
    }

    /// Vrai si hardened.
    #[must_use]
    pub const fn is_hardened(self) -> bool {
        matches!(self, ChildIndex::Hardened(_))
    }

    /// Sérialisation BIP-32 : `ser32(value | (0x80000000 si hardened))`.
    #[must_use]
    fn serialize(self) -> [u8; 4] {
        let raw = if self.is_hardened() {
            self.value() | 0x8000_0000
        } else {
            self.value()
        };
        raw.to_be_bytes()
    }

    /// Parse un segment de chemin (`0`, `0'`, `0h`, `0H`).
    fn parse(s: &str) -> Result<Self, HdError> {
        let (num_str, hardened) = match s.chars().last() {
            Some('\'') | Some('h') | Some('H') => (&s[..s.len() - 1], true),
            _ => (s, false),
        };
        let value: u32 = num_str
            .parse()
            .map_err(|e| HdError::InvalidPath(format!("bad index `{s}`: {e}")))?;
        if value >= 0x8000_0000 {
            return Err(HdError::InvalidPath(format!(
                "index {value} >= 2^31 (max authorized)"
            )));
        }
        Ok(if hardened {
            ChildIndex::Hardened(value)
        } else {
            ChildIndex::Normal(value)
        })
    }
}

// --- DerivationPath --------------------------------------------------------

/// Chemin de dérivation HD (`m/44'/60'/0'/0/0`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivationPath(Vec<ChildIndex>);

impl DerivationPath {
    /// Parse un chemin `"m/..."`.
    ///
    /// ## Accepté
    ///
    /// - `m` seul (chemin vide).
    /// - `m/0`, `m/0'`, `m/0h`, `m/0H`.
    /// - Combinaisons : `m/44'/100001'/0'/0'/0'`.
    ///
    /// ## Refusé
    ///
    /// - Préfixe autre que `m`.
    /// - Index `>= 2^31`.
    /// - Segment vide, `m0`, `m/`.
    pub fn parse(s: &str) -> Result<Self, HdError> {
        let s = s.trim();
        if !s.starts_with('m') {
            return Err(HdError::InvalidPath(format!(
                "must start with 'm', got '{s}'"
            )));
        }
        let rest = &s[1..];
        if rest.is_empty() {
            return Ok(Self(Vec::new()));
        }
        if !rest.starts_with('/') {
            return Err(HdError::InvalidPath(format!(
                "expected '/' after 'm', got '{rest}'"
            )));
        }
        let body = &rest[1..];
        if body.is_empty() {
            return Err(HdError::InvalidPath("trailing '/' with no index".into()));
        }
        let mut out = Vec::new();
        for part in body.split('/') {
            if part.is_empty() {
                return Err(HdError::InvalidPath("empty index segment".into()));
            }
            out.push(ChildIndex::parse(part)?);
        }
        Ok(Self(out))
    }

    /// Segments du chemin.
    #[must_use]
    pub fn as_slice(&self) -> &[ChildIndex] {
        &self.0
    }

    /// Nombre de segments.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Vrai si le chemin est vide (`m` seul).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("m")?;
        for c in &self.0 {
            match c {
                ChildIndex::Normal(v) => write!(f, "/{v}")?,
                ChildIndex::Hardened(v) => write!(f, "/{v}'")?,
            }
        }
        Ok(())
    }
}

// --- HMAC helper -----------------------------------------------------------

fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = HmacSha512::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    out
}

fn field_bytes_from_array(bytes: &[u8; 32]) -> FieldBytes {
    let mut fb = FieldBytes::default();
    fb.copy_from_slice(bytes);
    fb
}

// --- BIP-32 (secp256k1) ----------------------------------------------------

const BIP32_MASTER_KEY: &[u8] = b"Bitcoin seed";

/// Clé étendue secp256k1 (BIP-32).
///
/// Voir la documentation du module pour les choix d'implémentation.
pub struct XPrvSecp256k1 {
    private_key: Zeroizing<[u8; 32]>,
    chain_code: [u8; 32],
}

impl XPrvSecp256k1 {
    /// Master depuis un seed (16-64 bytes).
    ///
    /// `I = HMAC-SHA512("Bitcoin seed", seed)`, `k = IL`, `c = IR`.
    ///
    /// # Erreurs
    ///
    /// [`HdError::InvalidPath`] si le seed n'a pas une longueur valide
    /// (16-64 bytes). [`HdError::InvalidChildKey`] si `IL >= n` ou
    /// `IL == 0` (probabilité < 2^-127).
    pub fn from_seed(seed: &[u8]) -> Result<Self, HdError> {
        if seed.len() < 16 || seed.len() > 64 {
            return Err(HdError::InvalidPath(format!(
                "seed must be 16-64 bytes, got {}",
                seed.len()
            )));
        }
        let i = hmac_sha512(BIP32_MASTER_KEY, seed);
        let mut key = [0u8; 32];
        key.copy_from_slice(&i[..32]);
        let mut chain = [0u8; 32];
        chain.copy_from_slice(&i[32..]);

        if Option::<Scalar>::from(Scalar::from_repr(field_bytes_from_array(&key))).is_none() {
            return Err(HdError::InvalidChildKey { index: 0 });
        }
        Ok(Self {
            private_key: Zeroizing::new(key),
            chain_code: chain,
        })
    }

    /// Dérive l'enfant à `index`.
    ///
    /// # Erreurs
    ///
    /// [`HdError::InvalidChildKey`] si `parse256(IL) >= n` ou `ki == 0`
    /// (probabilité < 2^-127, documenté).
    pub fn derive_child(&self, index: ChildIndex) -> Result<Self, HdError> {
        let mut data = Vec::with_capacity(37);
        if index.is_hardened() {
            data.push(0x00);
            data.extend_from_slice(&*self.private_key);
        } else {
            data.extend_from_slice(&self.public_key_compressed());
        }
        data.extend_from_slice(&index.serialize());

        let i = hmac_sha512(&self.chain_code, &data);
        let mut il = [0u8; 32];
        il.copy_from_slice(&i[..32]);
        let mut ir = [0u8; 32];
        ir.copy_from_slice(&i[32..]);

        let il_scalar: Scalar = Option::<Scalar>::from(Scalar::from_repr(field_bytes_from_array(
            &il,
        )))
        .ok_or(HdError::InvalidChildKey {
            index: index.value(),
        })?;

        let kpar_scalar: Scalar =
            Option::<Scalar>::from(Scalar::from_repr(field_bytes_from_array(&self.private_key)))
                .expect("parent key was validated at construction");

        let ki_scalar = il_scalar + kpar_scalar;
        let ki_bytes: [u8; 32] = {
            let mut b = [0u8; 32];
            b.copy_from_slice(ki_scalar.to_bytes().as_slice());
            b
        };

        if ki_bytes.iter().all(|b| *b == 0) {
            return Err(HdError::InvalidChildKey {
                index: index.value(),
            });
        }

        Ok(Self {
            private_key: Zeroizing::new(ki_bytes),
            chain_code: ir,
        })
    }

    /// Dérive le long d'un chemin complet.
    pub fn derive_path(&self, path: &DerivationPath) -> Result<Self, HdError> {
        let mut cur = Self {
            private_key: Zeroizing::new(*self.private_key),
            chain_code: self.chain_code,
        };
        for &idx in path.as_slice() {
            cur = cur.derive_child(idx)?;
        }
        Ok(cur)
    }

    /// Clé publique **compressée** (33 bytes, préfixe `0x02`/`0x03`).
    #[must_use]
    pub fn public_key_compressed(&self) -> [u8; 33] {
        let scalar: Scalar =
            Option::<Scalar>::from(Scalar::from_repr(field_bytes_from_array(&self.private_key)))
                .expect("private key was validated at construction");
        let point = ProjectivePoint::GENERATOR * scalar;
        let affine = point.to_affine();
        let encoded = affine.to_encoded_point(true);
        let mut out = [0u8; 33];
        out.copy_from_slice(encoded.as_bytes());
        out
    }

    /// Clé publique **non compressée** (65 bytes, préfixe `0x04`).
    ///
    /// Adresse EVM : `Keccak256(pubkey[1..])[12..]`.
    #[must_use]
    pub fn public_key_uncompressed(&self) -> [u8; 65] {
        let scalar: Scalar =
            Option::<Scalar>::from(Scalar::from_repr(field_bytes_from_array(&self.private_key)))
                .expect("private key was validated at construction");
        let point = ProjectivePoint::GENERATOR * scalar;
        let affine = point.to_affine();
        let encoded = affine.to_encoded_point(false);
        let mut out = [0u8; 65];
        out.copy_from_slice(encoded.as_bytes());
        out
    }

    /// Accès brut à la clé privée.
    ///
    /// **Sensible** : à utiliser uniquement pour reconstruire un keypair
    /// dans un autre crate (ex. `sango-wallet::EvmKeypair::from_secret`).
    /// Ne pas logger, ne pas comparer en clair, ne pas persister sans
    /// chiffrement.
    #[must_use]
    pub fn private_key(&self) -> &[u8; 32] {
        &self.private_key
    }

    /// Chain code BIP-32.
    ///
    /// **Sensible** : combiné à la clé privée, il permet de dériver tous
    /// les enfants.
    #[must_use]
    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }

    /// Reconstruit un `k256::ecdsa::SigningKey`.
    ///
    /// Préféré à `private_key()` quand l'appelant veut signer.
    pub fn to_signing_key(&self) -> Result<k256::ecdsa::SigningKey, HdError> {
        k256::ecdsa::SigningKey::from_bytes(&field_bytes_from_array(&self.private_key))
            .map_err(|_| HdError::InvalidChildKey { index: 0 })
    }
}

impl fmt::Debug for XPrvSecp256k1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XPrvSecp256k1")
            .field("private_key", &"<redacted>")
            .field("chain_code", &"<redacted>")
            .finish()
    }
}

// --- SLIP-0010 (Ed25519) ---------------------------------------------------

const SLIP10_ED25519_MASTER_KEY: &[u8] = b"ed25519 seed";

/// Clé étendue Ed25519 (SLIP-0010).
///
/// ## Hardened uniquement
///
/// SLIP-0010 n'autorise que la dérivation **hardened** pour Ed25519.
/// Toute tentative de dériver un index `Normal(_)` renvoie
/// [`HdError::Ed25519RequiresHardened`].
pub struct XPrvEd25519 {
    private_key: Zeroizing<[u8; 32]>,
    chain_code: [u8; 32],
}

impl XPrvEd25519 {
    /// Master depuis un seed (16-64 bytes).
    ///
    /// `I = HMAC-SHA512("ed25519 seed", seed)`, `k = IL`, `c = IR`.
    ///
    /// Ne peut pas échouer : SLIP-0010 Ed25519 n'impose aucune contrainte
    /// sur `IL` (contrairement à BIP-32 secp256k1).
    #[must_use]
    pub fn from_seed(seed: &[u8]) -> Self {
        let i = hmac_sha512(SLIP10_ED25519_MASTER_KEY, seed);
        let mut key = [0u8; 32];
        key.copy_from_slice(&i[..32]);
        let mut chain = [0u8; 32];
        chain.copy_from_slice(&i[32..]);
        Self {
            private_key: Zeroizing::new(key),
            chain_code: chain,
        }
    }

    /// Dérive l'enfant hardened à `index`.
    ///
    /// # Erreurs
    ///
    /// [`HdError::Ed25519RequiresHardened`] si `index` est `Normal(_)`.
    pub fn derive_child(&self, index: ChildIndex) -> Result<Self, HdError> {
        if !index.is_hardened() {
            return Err(HdError::Ed25519RequiresHardened {
                index: index.value(),
            });
        }
        let mut data = Vec::with_capacity(37);
        data.push(0x00);
        data.extend_from_slice(&*self.private_key);
        data.extend_from_slice(&index.serialize());

        let i = hmac_sha512(&self.chain_code, &data);
        let mut key = [0u8; 32];
        key.copy_from_slice(&i[..32]);
        let mut chain = [0u8; 32];
        chain.copy_from_slice(&i[32..]);
        Ok(Self {
            private_key: Zeroizing::new(key),
            chain_code: chain,
        })
    }

    /// Dérive le long d'un chemin complet.
    ///
    /// # Erreurs
    ///
    /// Toute composante `Normal(_)` du chemin fait échouer la dérivation.
    pub fn derive_path(&self, path: &DerivationPath) -> Result<Self, HdError> {
        let mut cur = Self {
            private_key: Zeroizing::new(*self.private_key),
            chain_code: self.chain_code,
        };
        for &idx in path.as_slice() {
            cur = cur.derive_child(idx)?;
        }
        Ok(cur)
    }

    /// Reconstruit une paire de clés Sango native.
    ///
    /// Préféré à `private_key()` quand l'appelant veut signer ou dériver
    /// une adresse native.
    #[must_use]
    pub fn to_native_keypair(&self) -> NativeKeypair {
        NativeKeypair::from_seed(*self.private_key)
    }

    /// Clé publique Ed25519.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.to_native_keypair().public_key()
    }

    /// Accès brut à la clé privée Ed25519.
    ///
    /// **Sensible** : voir [`XPrvSecp256k1::private_key`].
    #[must_use]
    pub fn private_key(&self) -> &[u8; 32] {
        &self.private_key
    }

    /// Chain code SLIP-0010.
    ///
    /// **Sensible** : voir [`XPrvSecp256k1::chain_code`].
    #[must_use]
    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }
}

impl fmt::Debug for XPrvEd25519 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XPrvEd25519")
            .field("private_key", &"<redacted>")
            .field("chain_code", &"<redacted>")
            .finish()
    }
}

// --- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_decode(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    // --- ChildIndex --------------------------------------------------------

    #[test]
    fn child_index_parse_normal() {
        assert_eq!(ChildIndex::parse("0").unwrap(), ChildIndex::Normal(0));
        assert_eq!(ChildIndex::parse("42").unwrap(), ChildIndex::Normal(42));
    }

    #[test]
    fn child_index_parse_hardened() {
        assert_eq!(ChildIndex::parse("0'").unwrap(), ChildIndex::Hardened(0));
        assert_eq!(ChildIndex::parse("0h").unwrap(), ChildIndex::Hardened(0));
        assert_eq!(ChildIndex::parse("0H").unwrap(), ChildIndex::Hardened(0));
        assert_eq!(ChildIndex::parse("42'").unwrap(), ChildIndex::Hardened(42));
    }

    #[test]
    fn child_index_parse_rejects_out_of_range() {
        assert!(ChildIndex::parse("2147483648").is_err()); // 2^31
        assert!(ChildIndex::parse("4294967295").is_err());
        assert!(ChildIndex::parse("2147483648'").is_err());
    }

    #[test]
    fn child_index_parse_rejects_non_numeric() {
        assert!(ChildIndex::parse("abc").is_err());
        assert!(ChildIndex::parse("").is_err());
    }

    #[test]
    fn child_index_serialize_normal() {
        assert_eq!(ChildIndex::Normal(0).serialize(), [0, 0, 0, 0]);
        assert_eq!(ChildIndex::Normal(1).serialize(), [0, 0, 0, 1]);
        assert_eq!(
            ChildIndex::Normal(0x7FFF_FFFF).serialize(),
            [0x7F, 0xFF, 0xFF, 0xFF]
        );
    }

    #[test]
    fn child_index_serialize_hardened() {
        assert_eq!(ChildIndex::Hardened(0).serialize(), [0x80, 0, 0, 0]);
        assert_eq!(ChildIndex::Hardened(1).serialize(), [0x80, 0, 0, 1]);
        assert_eq!(
            ChildIndex::Hardened(0x7FFF_FFFF).serialize(),
            [0xFF, 0xFF, 0xFF, 0xFF]
        );
    }

    #[test]
    fn child_index_value_returns_logical_value() {
        assert_eq!(ChildIndex::Normal(5).value(), 5);
        assert_eq!(ChildIndex::Hardened(5).value(), 5);
    }

    #[test]
    fn child_index_is_hardened() {
        assert!(!ChildIndex::Normal(0).is_hardened());
        assert!(ChildIndex::Hardened(0).is_hardened());
    }

    // --- DerivationPath ----------------------------------------------------

    #[test]
    fn path_parse_m_alone() {
        let p = DerivationPath::parse("m").unwrap();
        assert!(p.is_empty());
    }

    #[test]
    fn path_parse_simple() {
        let p = DerivationPath::parse("m/44'/60'/0'/0/0").unwrap();
        assert_eq!(p.len(), 5);
        assert_eq!(p.as_slice()[0], ChildIndex::Hardened(44));
        assert_eq!(p.as_slice()[1], ChildIndex::Hardened(60));
        assert_eq!(p.as_slice()[2], ChildIndex::Hardened(0));
        assert_eq!(p.as_slice()[3], ChildIndex::Normal(0));
        assert_eq!(p.as_slice()[4], ChildIndex::Normal(0));
    }

    #[test]
    fn path_parse_all_hardened() {
        let p = DerivationPath::parse("m/44'/100001'/0'/0'/0'").unwrap();
        assert_eq!(p.len(), 5);
        for c in p.as_slice() {
            assert!(c.is_hardened());
        }
    }

    #[test]
    fn path_parse_rejects_bad_prefix() {
        assert!(DerivationPath::parse("n/0").is_err());
        assert!(DerivationPath::parse("").is_err());
        assert!(DerivationPath::parse("m0").is_err());
    }

    #[test]
    fn path_parse_rejects_trailing_slash() {
        assert!(DerivationPath::parse("m/").is_err());
        assert!(DerivationPath::parse("m/0/").is_err());
    }

    #[test]
    fn path_display_roundtrip() {
        for s in [
            "m",
            "m/0",
            "m/0'",
            "m/44'/60'/0'/0/0",
            "m/44'/100001'/0'/0'/0'",
            "m/0'/1/2'/2/1000000000",
        ] {
            let p = DerivationPath::parse(s).unwrap();
            assert_eq!(p.to_string(), s);
        }
    }

    // --- BIP-32 golden vectors (Test Vector 1, chaque étape) --------------

    /// Test Vector 1 du BIP-32, vérifie **chaque étape** du chemin.
    #[test]
    fn bip32_test_vector_1_step_by_step() {
        let seed = hex_decode("000102030405060708090a0b0c0d0e0f");
        let root = XPrvSecp256k1::from_seed(&seed).unwrap();

        let check = |x: &XPrvSecp256k1, expected_cc: &str, expected_key: &str| {
            assert_eq!(hex::encode(x.chain_code()), expected_cc, "chain code");
            assert_eq!(hex::encode(x.private_key()), expected_key, "private key");
        };

        // m
        check(
            &root,
            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
        );

        // m/0'
        let x = root.derive_child(ChildIndex::Hardened(0)).unwrap();
        check(
            &x,
            "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
        );

        // m/0'/1
        let x = x.derive_child(ChildIndex::Normal(1)).unwrap();
        check(
            &x,
            "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19",
            "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
        );

        // m/0'/1/2'
        let x = x.derive_child(ChildIndex::Hardened(2)).unwrap();
        check(
            &x,
            "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f",
            "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
        );

        // m/0'/1/2'/2
        let x = x.derive_child(ChildIndex::Normal(2)).unwrap();
        check(
            &x,
            "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd",
            "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4",
        );

        // m/0'/1/2'/2/1000000000
        let x = x.derive_child(ChildIndex::Normal(1_000_000_000)).unwrap();
        check(
            &x,
            "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e",
            "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8",
        );
    }

    #[test]
    fn bip32_derive_path_matches_step_by_step() {
        let seed = hex_decode("000102030405060708090a0b0c0d0e0f");
        let root = XPrvSecp256k1::from_seed(&seed).unwrap();

        let path = DerivationPath::parse("m/0'/1/2'/2/1000000000").unwrap();
        let direct = root.derive_path(&path).unwrap();

        let step = root
            .derive_child(ChildIndex::Hardened(0))
            .unwrap()
            .derive_child(ChildIndex::Normal(1))
            .unwrap()
            .derive_child(ChildIndex::Hardened(2))
            .unwrap()
            .derive_child(ChildIndex::Normal(2))
            .unwrap()
            .derive_child(ChildIndex::Normal(1_000_000_000))
            .unwrap();

        assert_eq!(direct.private_key(), step.private_key());
        assert_eq!(direct.chain_code(), step.chain_code());
    }

    #[test]
    fn bip32_rejects_short_seed() {
        assert!(XPrvSecp256k1::from_seed(&[0u8; 8]).is_err());
    }

    #[test]
    fn bip32_rejects_long_seed() {
        assert!(XPrvSecp256k1::from_seed(&[0u8; 100]).is_err());
    }

    // --- SLIP-0010 golden vectors (Test Vector 1, chaque étape) -----------

    /// Test Vector 1 de SLIP-0010 Ed25519, vérifie **chaque étape** du chemin.
    #[test]
    fn slip10_test_vector_1_step_by_step() {
        let seed = hex_decode("000102030405060708090a0b0c0d0e0f");
        let root = XPrvEd25519::from_seed(&seed);

        let check = |x: &XPrvEd25519, expected_cc: &str, expected_key: &str| {
            assert_eq!(hex::encode(x.chain_code()), expected_cc, "chain code");
            assert_eq!(hex::encode(x.private_key()), expected_key, "private key");
        };

        // m
        check(
            &root,
            "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb",
            "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
        );

        // m/0'
        let x = root.derive_child(ChildIndex::Hardened(0)).unwrap();
        check(
            &x,
            "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69",
            "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
        );

        // m/0'/1'
        let x = x.derive_child(ChildIndex::Hardened(1)).unwrap();
        check(
            &x,
            "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14",
            "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
        );

        // m/0'/1'/2'
        let x = x.derive_child(ChildIndex::Hardened(2)).unwrap();
        check(
            &x,
            "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c",
            "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
        );

        // m/0'/1'/2'/2'
        let x = x.derive_child(ChildIndex::Hardened(2)).unwrap();
        check(
            &x,
            "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc",
            "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
        );

        // m/0'/1'/2'/2'/1000000000'
        let x = x.derive_child(ChildIndex::Hardened(1_000_000_000)).unwrap();
        check(
            &x,
            "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230",
            "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
        );
    }

    #[test]
    fn slip10_derive_path_matches_step_by_step() {
        let seed = hex_decode("000102030405060708090a0b0c0d0e0f");
        let root = XPrvEd25519::from_seed(&seed);

        let path = DerivationPath::parse("m/0'/1'/2'/2'/1000000000'").unwrap();
        let direct = root.derive_path(&path).unwrap();

        let step = root
            .derive_child(ChildIndex::Hardened(0))
            .unwrap()
            .derive_child(ChildIndex::Hardened(1))
            .unwrap()
            .derive_child(ChildIndex::Hardened(2))
            .unwrap()
            .derive_child(ChildIndex::Hardened(2))
            .unwrap()
            .derive_child(ChildIndex::Hardened(1_000_000_000))
            .unwrap();

        assert_eq!(direct.private_key(), step.private_key());
        assert_eq!(direct.chain_code(), step.chain_code());
    }

    #[test]
    fn slip10_rejects_normal_index() {
        let seed = [0u8; 32];
        let root = XPrvEd25519::from_seed(&seed);
        let err = root.derive_child(ChildIndex::Normal(0)).unwrap_err();
        assert!(matches!(err, HdError::Ed25519RequiresHardened { .. }));
    }

    #[test]
    fn slip10_derive_path_rejects_normal_in_middle() {
        let seed = [0u8; 32];
        let root = XPrvEd25519::from_seed(&seed);
        let path = DerivationPath::parse("m/0'/1/2'").unwrap();
        let err = root.derive_path(&path).unwrap_err();
        assert!(matches!(err, HdError::Ed25519RequiresHardened { .. }));
    }

    // --- Debug redaction --------------------------------------------------

    #[test]
    fn secp256k1_debug_does_not_leak_secrets() {
        let seed = hex_decode("000102030405060708090a0b0c0d0e0f");
        let x = XPrvSecp256k1::from_seed(&seed).unwrap();
        let s = format!("{x:?}");
        assert!(s.contains("redacted"));
        // Le préfixe de la vraie clé privée ne doit PAS apparaître.
        assert!(!s.contains("e8f32e72"));
        // Le préfixe du vrai chain code ne doit PAS apparaître.
        assert!(!s.contains("873dff81"));
    }

    #[test]
    fn ed25519_debug_does_not_leak_secrets() {
        let seed = [0x42u8; 32];
        let x = XPrvEd25519::from_seed(&seed);
        let s = format!("{x:?}");
        assert!(s.contains("redacted"));
    }

    // --- Ed25519 → NativeKeypair ------------------------------------------

    #[test]
    fn ed25519_to_native_keypair_is_deterministic() {
        let seed = hex_decode("000102030405060708090a0b0c0d0e0f");
        let x = XPrvEd25519::from_seed(&seed);
        let kp1 = x.to_native_keypair();
        let kp2 = x.to_native_keypair();
        assert_eq!(kp1.public_key(), kp2.public_key());
    }

    #[test]
    fn ed25519_public_key_matches_keypair() {
        let seed = [0x11u8; 32];
        let x = XPrvEd25519::from_seed(&seed);
        assert_eq!(x.public_key(), x.to_native_keypair().public_key());
    }
}
