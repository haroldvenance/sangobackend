//! Encodage Bech32m des adresses natives Sango.
//!
//! ## Spécification normative (verrouillée avec le frontend)
//!
//! - **Variante** : Bech32m (BIP-350).
//! - **HRP** :
//!   - `sango`  → mainnet
//!   - `tsango` → testnet **et** devnet
//! - **Payload** : les **20 bytes bruts** retournés par
//!   [`crate::derive_native_address`]. **Aucun préfixe**, **aucun byte
//!   de version**, **aucun byte de type**.
//! - Le domain separator `"SANGO/ADDRESS/V1"` vit **uniquement** dans
//!   le hash de dérivation — il **n'apparaît jamais** dans la chaîne
//!   Bech32m.
//!
//! ## Orthogonalité
//!
//! ```text
//! derive_native_address(pk) → 20 bytes      (Keccak + domain)
//! encode_native_address(addr, network)      (Bech32m, ce module)
//! ```
//!
//! Les deux étapes sont indépendantes. Modifier l'encodage utilisateur
//! (Bech32m → autre) n'affecte **jamais** les hashes consensus.
//!
//! ## Non-consensus
//!
//! Cette transformation est **purement présentationnelle**. Le
//! `state_root`, le `block_hash`, les signatures et les clés d'état
//! utilisent les 20 bytes bruts. Ne **jamais** hasher une chaîne
//! Bech32m dans du code consensus.

use bech32::{Bech32m, Hrp};
use thiserror::Error;

use sango_primitives::NativeAddress;

/// Réseau Sango, qui détermine le HRP Bech32m.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Network {
    /// Réseau principal. HRP : `sango`.
    Mainnet,
    /// Réseau de test public. HRP : `tsango`.
    Testnet,
    /// Réseau de développement local. HRP : `tsango` (aligné sur
    /// testnet : on ne crée pas de 3ᵉ HRP).
    Devnet,
}

impl Network {
    /// HRP normatif du réseau.
    #[must_use]
    pub const fn hrp(self) -> &'static str {
        match self {
            Network::Mainnet => "sango",
            Network::Testnet => "tsango",
            Network::Devnet => "tsango",
        }
    }

    /// Parse un HRP en réseau.
    ///
    /// `sango` → Mainnet ; `tsango` → Testnet (Devnet n'est pas
    /// distinguable au niveau HRP).
    pub fn from_hrp(hrp: &str) -> Option<Self> {
        match hrp {
            "sango" => Some(Network::Mainnet),
            "tsango" => Some(Network::Testnet),
            _ => None,
        }
    }
}

/// Erreur produite par l'encodage / décodage Bech32m.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Bech32mError {
    /// L'encodage Bech32m a échoué (longueur, alphabet, etc.).
    #[error("bech32m encode failed: {0}")]
    Encode(String),

    /// Le décodage Bech32m a échoué (checksum, alphabet, mix-case…).
    #[error("bech32m decode failed: {0}")]
    Decode(String),

    /// Le HRP ne correspond à aucun réseau connu.
    #[error("unknown HRP: {0}")]
    UnknownHrp(String),

    /// Le HRP ne correspond pas au réseau attendu.
    #[error("HRP mismatch: expected {expected}, got {got}")]
    HrpMismatch {
        /// HRP attendu.
        expected: &'static str,
        /// HRP reçu.
        got: String,
    },

    /// Le payload ne fait pas exactement 20 bytes.
    #[error("invalid payload length: expected 20, got {got}")]
    InvalidPayloadLength {
        /// Longueur reçue.
        got: usize,
    },
}

/// Helper privé : décode une chaîne en **vérifiant explicitement** que
/// le checksum est Bech32m (BIP-350), pas Bech32 classique (BIP-173).
///
/// `bech32::decode` fait de l'auto-détection et accepte les deux
/// variantes ; on force donc la vérification par ré-encodage : si le
/// résultat ré-encodé en Bech32m diffère de la chaîne originale, c'est
/// que l'original n'était pas du Bech32m.
fn decode_checked_bech32m(s: &str) -> Result<(Hrp, Vec<u8>), Bech32mError> {
    let (hrp, bytes) = bech32::decode(s).map_err(|e| Bech32mError::Decode(e.to_string()))?;
    let reencoded =
        bech32::encode::<Bech32m>(hrp, &bytes).map_err(|e| Bech32mError::Decode(e.to_string()))?;
    if reencoded != s {
        return Err(Bech32mError::Decode(
            "not a valid Bech32m string (checksum mismatch — maybe Bech32 classic?)".into(),
        ));
    }
    Ok((hrp, bytes))
}

/// Encode une adresse native en chaîne Bech32m pour un réseau donné.
///
/// ## Exemple
///
/// ```ignore
/// let addr = NativeAddress::from_bytes([0xaa; 20]);
/// let s = encode_native_address(addr, Network::Mainnet);
/// assert!(s.starts_with("sango1"));
/// ```
#[must_use]
pub fn encode_native_address(addr: NativeAddress, network: Network) -> String {
    let hrp = Hrp::parse(network.hrp()).expect("HRP constantes valides");
    bech32::encode::<Bech32m>(hrp, addr.as_bytes()).expect("20 bytes < limite Bech32m (90 chars)")
}

/// Décode une chaîne Bech32m et vérifie qu'elle correspond au réseau
/// attendu.
///
/// # Erreurs
///
/// - [`Bech32mError::Decode`] si la chaîne n'est pas du Bech32m valide.
/// - [`Bech32mError::UnknownHrp`] si le HRP n'est ni `sango` ni `tsango`.
/// - [`Bech32mError::HrpMismatch`] si le réseau diffère de `expected`.
/// - [`Bech32mError::InvalidPayloadLength`] si le payload ≠ 20 bytes.
pub fn decode_native_address(s: &str, expected: Network) -> Result<NativeAddress, Bech32mError> {
    let (hrp, bytes) = decode_checked_bech32m(s)?;
    let hrp_str = hrp.as_str();

    let found =
        Network::from_hrp(hrp_str).ok_or_else(|| Bech32mError::UnknownHrp(hrp_str.to_string()))?;

    // Note : Devnet et Testnet partagent le HRP `tsango`. On accepte
    // donc indifféremment `tsango` pour l'un ou l'autre.
    let hrp_matches = match expected {
        Network::Mainnet => found == Network::Mainnet,
        Network::Testnet | Network::Devnet => found != Network::Mainnet,
    };
    if !hrp_matches {
        return Err(Bech32mError::HrpMismatch {
            expected: expected.hrp(),
            got: hrp_str.to_string(),
        });
    }

    if bytes.len() != 20 {
        return Err(Bech32mError::InvalidPayloadLength { got: bytes.len() });
    }
    let mut raw = [0u8; 20];
    raw.copy_from_slice(&bytes);
    Ok(NativeAddress::from_bytes(raw))
}

/// Décode une chaîne Bech32m **sans présumer** du réseau.
///
/// Retourne le couple `(adresse, réseau)` où `network` est
/// `Mainnet` ou `Testnet` (Devnet n'est pas distinguable).
pub fn try_decode_any_network(s: &str) -> Result<(NativeAddress, Network), Bech32mError> {
    let (hrp, bytes) = decode_checked_bech32m(s)?;
    let network = Network::from_hrp(hrp.as_str())
        .ok_or_else(|| Bech32mError::UnknownHrp(hrp.as_str().to_string()))?;
    if bytes.len() != 20 {
        return Err(Bech32mError::InvalidPayloadLength { got: bytes.len() });
    }
    let mut raw = [0u8; 20];
    raw.copy_from_slice(&bytes);
    Ok((NativeAddress::from_bytes(raw), network))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> NativeAddress {
        NativeAddress::from_bytes([byte; 20])
    }

    // --- HRP -------------------------------------------------------------

    #[test]
    fn hrp_mainnet_is_sango() {
        assert_eq!(Network::Mainnet.hrp(), "sango");
    }

    #[test]
    fn hrp_testnet_and_devnet_are_tsango() {
        assert_eq!(Network::Testnet.hrp(), "tsango");
        assert_eq!(Network::Devnet.hrp(), "tsango");
    }

    #[test]
    fn from_hrp_roundtrip() {
        assert_eq!(Network::from_hrp("sango"), Some(Network::Mainnet));
        assert_eq!(Network::from_hrp("tsango"), Some(Network::Testnet));
        assert_eq!(Network::from_hrp("btc"), None);
        assert_eq!(Network::from_hrp("SANGO"), None);
    }

    // --- Encodage ---------------------------------------------------------

    #[test]
    fn mainnet_prefix_is_sango1() {
        let s = encode_native_address(addr(0xaa), Network::Mainnet);
        assert!(s.starts_with("sango1"), "got: {s}");
    }

    #[test]
    fn testnet_prefix_is_tsango1() {
        let s = encode_native_address(addr(0xaa), Network::Testnet);
        assert!(s.starts_with("tsango1"), "got: {s}");
    }

    #[test]
    fn mainnet_and_testnet_differ() {
        let a = encode_native_address(addr(0xaa), Network::Mainnet);
        let t = encode_native_address(addr(0xaa), Network::Testnet);
        assert_ne!(a, t);
    }

    #[test]
    fn encoding_is_deterministic() {
        let a = addr(0x11);
        let s1 = encode_native_address(a, Network::Mainnet);
        let s2 = encode_native_address(a, Network::Mainnet);
        assert_eq!(s1, s2);
    }

    #[test]
    fn different_addresses_give_different_strings() {
        let s1 = encode_native_address(addr(0x01), Network::Mainnet);
        let s2 = encode_native_address(addr(0x02), Network::Mainnet);
        assert_ne!(s1, s2);
    }

    // --- Roundtrip --------------------------------------------------------

    #[test]
    fn mainnet_roundtrip() {
        for b in [0x00, 0xaa, 0xff] {
            let original = addr(b);
            let s = encode_native_address(original, Network::Mainnet);
            let decoded = decode_native_address(&s, Network::Mainnet).unwrap();
            assert_eq!(decoded, original);
        }
    }

    #[test]
    fn testnet_roundtrip() {
        for b in [0x00, 0xaa, 0xff] {
            let original = addr(b);
            let s = encode_native_address(original, Network::Testnet);
            let decoded = decode_native_address(&s, Network::Testnet).unwrap();
            assert_eq!(decoded, original);
        }
    }

    #[test]
    fn devnet_decodes_as_tsango() {
        // Devnet utilise `tsango`. Une chaîne encodée pour Testnet doit
        // être décodable pour Devnet et vice-versa.
        let original = addr(0xcc);
        let s = encode_native_address(original, Network::Testnet);
        let decoded = decode_native_address(&s, Network::Devnet).unwrap();
        assert_eq!(decoded, original);
    }

    // --- try_decode_any_network -------------------------------------------

    #[test]
    fn try_decode_mainnet() {
        let original = addr(0xab);
        let s = encode_native_address(original, Network::Mainnet);
        let (decoded, net) = try_decode_any_network(&s).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(net, Network::Mainnet);
    }

    #[test]
    fn try_decode_testnet() {
        let original = addr(0xcd);
        let s = encode_native_address(original, Network::Testnet);
        let (decoded, net) = try_decode_any_network(&s).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(net, Network::Testnet);
    }

    // --- Rejets -----------------------------------------------------------

    #[test]
    fn hrp_mismatch_rejected() {
        let s = encode_native_address(addr(0xaa), Network::Mainnet);
        let err = decode_native_address(&s, Network::Testnet).unwrap_err();
        assert!(matches!(err, Bech32mError::HrpMismatch { .. }));
    }

    #[test]
    fn unknown_hrp_rejected() {
        // Reconstruire un Bech32m avec un HRP inconnu.
        let hrp = Hrp::parse("btc").unwrap();
        let s = bech32::encode::<Bech32m>(hrp, &[0xaa; 20]).unwrap();
        let err = try_decode_any_network(&s).unwrap_err();
        assert!(matches!(err, Bech32mError::UnknownHrp(_)));
    }

    #[test]
    fn invalid_string_rejected() {
        assert!(try_decode_any_network("not a bech32 string").is_err());
        assert!(try_decode_any_network("").is_err());
        assert!(try_decode_any_network("sango1INVALID").is_err());
    }

    #[test]
    fn wrong_payload_length_rejected() {
        // Bech32m avec payload de 10 bytes (pas 20).
        let hrp = Hrp::parse("sango").unwrap();
        let s = bech32::encode::<Bech32m>(hrp, &[0u8; 10]).unwrap();
        let err = try_decode_any_network(&s).unwrap_err();
        assert_eq!(err, Bech32mError::InvalidPayloadLength { got: 10 });
    }

    #[test]
    fn bech32_classic_rejected() {
        // Une chaîne Bech32 **classique** (pas m) doit être rejetée.
        // On encode avec `Bech32` (checksum original) et on essaie de
        // décoder avec notre fonction (qui attend Bech32m).
        use bech32::Bech32;
        let hrp = Hrp::parse("sango").unwrap();
        let s = bech32::encode::<Bech32>(hrp, &[0xaa; 20]).unwrap();
        // Soit le décodage échoue (checksum), soit il réussit mais
        // ne doit PAS être confondu avec une adresse valide — dans le
        // doute on teste que ça lève une erreur.
        assert!(try_decode_any_network(&s).is_err());
    }

    // --- Golden vectors ---------------------------------------------------

    /// Golden vector **normatif**.
    ///
    /// Adresse brute = `Keccak256("SANGO/ADDRESS/V1" || pk)[0..20]`
    /// pour le seed `[0x55; 32]`.
    ///
    /// Note : cette adresse est **le résultat d'une dérivation
    /// spécifique** ; le test ne fait que figer l'encodage Bech32m
    /// associé. Si l'encodage change, ce test casse = hard fork
    /// présentationnel (à documenter).
    #[test]
    fn golden_vector_known_address() {
        // 02291e07839d715a4c78b8585449b7e367aa01ab
        let raw = [
            0x02, 0x29, 0x1e, 0x07, 0x83, 0x9d, 0x71, 0x5a, 0x4c, 0x78, 0xb8, 0x58, 0x54, 0x49,
            0xb7, 0xe3, 0x67, 0xaa, 0x01, 0xab,
        ];
        let addr = NativeAddress::from_bytes(raw);

        let mainnet = encode_native_address(addr, Network::Mainnet);
        let testnet = encode_native_address(addr, Network::Testnet);

        // Vérifie les préfixes (HRP).
        assert!(mainnet.starts_with("sango1"));
        assert!(testnet.starts_with("tsango1"));

        // Roundtrip.
        assert_eq!(
            decode_native_address(&mainnet, Network::Mainnet).unwrap(),
            addr
        );
        assert_eq!(
            decode_native_address(&testnet, Network::Testnet).unwrap(),
            addr
        );

        // ⚠ Golden vectors **normatifs**, alignés byte-à-byte avec le
        // frontend (TS). Toute modification casse ce test = hard fork
        // présentationnel (à documenter + coordonner avec le frontend).
        assert_eq!(mainnet, "sango1qg53upurn4c45nrchpv9gjdhudn65qdtr5l9u6");
        assert_eq!(testnet, "tsango1qg53upurn4c45nrchpv9gjdhudn65qdtv3xlde");
    }
}
