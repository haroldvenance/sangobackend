//! Wallet V3 : mnemonic BIP-39 + dérivation HD multi-chain.
//!
//! ## Séparation avec `sango-crypto`
//!
//! Ce module vit dans `sango-wallet` (décision W4.a) : il combine des
//! primitives bas niveau (`Mnemonic`, `XPrvEd25519`, `XPrvSecp256k1`)
//! en une abstraction orientée usage applicatif.
//!
//! ## Pas de seed persisté
//!
//! L'état canonique est la **mnemonic + passphrase**, pas le seed BIP-39.
//! Le seed est dérivé à la demande (déterministe) puis effacé — voir
//! design doc W1 D6.
//!
//! ## Chemins HD
//!
//! - Sango natif : `m/44'/100001'/0'/0'/0'` (Ed25519, SLIP-0010, tous
//!   hardened).
//! - EVM : `m/44'/60'/0'/0/{index}` (secp256k1, BIP-44).

use zeroize::Zeroizing;

use sango_crypto::bech32m::Network;
use sango_crypto::ed25519::NativeKeypair;
use sango_crypto::hd::{DerivationPath, HdError, XPrvEd25519, XPrvSecp256k1};
use sango_crypto::mnemonic::{Mnemonic, MnemonicLength};

use crate::error::WalletError;
use crate::evm::EvmKeypair;

/// Coin type Sango sur devnet/testnet (non enregistré SLIP-0044).
///
/// **Mainnet** : à figer via SLIP-0044 (voir design doc W1 D4).
pub const SANGO_COIN_TYPE_TESTNET: u32 = 100_001;

/// Coin type EVM (Ethereum mainnet, partagé par les EVM chains).
pub const EVM_COIN_TYPE: u32 = 60;

/// Retourne le coin type Sango pour un réseau donné.
///
/// # Erreurs
///
/// [`WalletError::Usage`] pour `Network::Mainnet` : aucun wallet V3
/// mainnet n'est autorisé tant que le coin type n'est pas officiellement
/// figé (design doc W1 D4).
pub fn sango_coin_type(network: Network) -> Result<u32, WalletError> {
    match network {
        Network::Devnet | Network::Testnet => Ok(SANGO_COIN_TYPE_TESTNET),
        Network::Mainnet => Err(WalletError::Usage(
            "Sango mainnet coin type is not yet configured — \
             refusing to fall back to 100001"
                .into(),
        )),
    }
}

/// Chemin HD Sango natif (`m/44'/COIN'/0'/0'/{index}'`).
pub fn sango_hd_path(network: Network, account_index: u32) -> Result<DerivationPath, WalletError> {
    let coin = sango_coin_type(network)?;
    let s = format!("m/44'/{coin}'/0'/0'/{account_index}'");
    DerivationPath::parse(&s).map_err(|e| WalletError::Usage(format!("bad Sango path: {e}")))
}

/// Chemin HD EVM (`m/44'/60'/0'/0/{index}`).
///
/// Le dernier niveau est **non-hardened** : convention BIP-44 pour
/// Ethereum.
#[must_use]
pub fn evm_hd_path(account_index: u32) -> DerivationPath {
    let s = format!("m/44'/{EVM_COIN_TYPE}'/0'/0/{account_index}");
    DerivationPath::parse(&s).expect("constant EVM path is always valid")
}

/// Wallet V3 : mnemonic BIP-39 + passphrase optionnelle.
///
/// Le seed BIP-39 n'est **pas** persisté. Il est re-dérivé à chaque
/// appel de dérivation (`sango_keypair`, `evm_keypair`) puis effacé.
pub struct WalletV3 {
    mnemonic: Mnemonic,
    passphrase: Option<Zeroizing<String>>,
}

impl WalletV3 {
    /// Construit depuis une mnemonic déjà parsée.
    pub fn from_mnemonic(mnemonic: Mnemonic, passphrase: Option<String>) -> Self {
        Self {
            mnemonic,
            passphrase: passphrase.map(Zeroizing::new),
        }
    }

    /// Parse une mnemonic puis construit le wallet.
    pub fn from_mnemonic_str(s: &str, passphrase: Option<String>) -> Result<Self, WalletError> {
        let m =
            Mnemonic::parse(s).map_err(|e| WalletError::Usage(format!("invalid mnemonic: {e}")))?;
        Ok(Self::from_mnemonic(m, passphrase))
    }

    /// Génère une nouvelle mnemonic via le CSPRNG de l'OS.
    pub fn generate(length: MnemonicLength) -> Result<Self, WalletError> {
        let m = Mnemonic::generate(length)
            .map_err(|e| WalletError::Usage(format!("mnemonic generation: {e}")))?;
        Ok(Self::from_mnemonic(m, None))
    }

    /// Vrai si une passphrase BIP-39 non-vide est utilisée.
    #[must_use]
    pub fn passphrase_used(&self) -> bool {
        self.passphrase
            .as_ref()
            .is_some_and(|p| !p.as_str().is_empty())
    }

    /// Dérive la clé native Sango à l'index d'account donné.
    ///
    /// # Erreurs
    ///
    /// - [`WalletError::Usage`] si `network == Mainnet` (coin type non
    ///   figé).
    /// - [`WalletError::Usage`] en cas d'erreur HD (théorique).
    pub fn sango_keypair(
        &self,
        network: Network,
        account_index: u32,
    ) -> Result<NativeKeypair, WalletError> {
        let seed = self.bip39_seed();
        let xprv = XPrvEd25519::from_seed(&seed[..]);
        let path = sango_hd_path(network, account_index)?;
        let derived = xprv.derive_path(&path).map_err(map_hd_err)?;
        Ok(derived.to_native_keypair())
    }

    /// Dérive la clé EVM à l'index d'account donné.
    pub fn evm_keypair(&self, account_index: u32) -> Result<EvmKeypair, WalletError> {
        let seed = self.bip39_seed();
        let xprv = XPrvSecp256k1::from_seed(&seed[..]).map_err(map_hd_err)?;
        let path = evm_hd_path(account_index);
        let derived = xprv.derive_path(&path).map_err(map_hd_err)?;
        // Note : `*derived.private_key()` fait une copie stack du secret.
        // Cette copie vit très peu de temps (elle est immédiatement
        // absorbée par `SigningKey::from_bytes`, qui est ZeroizeOnDrop).
        // Acceptable en W4, à raffiner si besoin.
        EvmKeypair::from_secret(*derived.private_key())
    }

    /// Dérive le keypair natif Sango avec une passphrase BIP-39 **passée
    /// à l'appel**.
    ///
    /// ## Différence avec [`Self::sango_keypair`]
    ///
    /// `sango_keypair` utilise la passphrase mémorisée à la
    /// construction du wallet. Cette variante utilise une passphrase
    /// **dynamique**, ce qui permet de charger un keyfile V3 sans
    /// connaître la passphrase, puis de la fournir uniquement au moment
    /// de la dérivation (modèle préféré W4.c).
    pub fn sango_keypair_with_passphrase(
        &self,
        network: Network,
        account_index: u32,
        passphrase: Option<&str>,
    ) -> Result<NativeKeypair, WalletError> {
        let seed = self.mnemonic.to_seed(passphrase);
        let xprv = XPrvEd25519::from_seed(&seed[..]);
        let path = sango_hd_path(network, account_index)?;
        let derived = xprv.derive_path(&path).map_err(map_hd_err)?;
        Ok(derived.to_native_keypair())
    }

    /// Dérive le keypair EVM avec une passphrase BIP-39 dynamique.
    pub fn evm_keypair_with_passphrase(
        &self,
        account_index: u32,
        passphrase: Option<&str>,
    ) -> Result<EvmKeypair, WalletError> {
        let seed = self.mnemonic.to_seed(passphrase);
        let xprv = XPrvSecp256k1::from_seed(&seed[..]).map_err(map_hd_err)?;
        let path = evm_hd_path(account_index);
        let derived = xprv.derive_path(&path).map_err(map_hd_err)?;
        EvmKeypair::from_secret(*derived.private_key())
    }

    /// Retourne une copie effaçable de la mnemonic.
    ///
    /// **`pub(crate)`** : usage interne (chiffrement keyfile V3,
    /// commande `export-mnemonic`).
    #[must_use]
    pub(crate) fn mnemonic_owned(&self) -> Zeroizing<String> {
        self.mnemonic.expose()
    }

    /// Calcule la seed BIP-39 (64 bytes) à la demande.
    fn bip39_seed(&self) -> Zeroizing<[u8; 64]> {
        // `Zeroizing<String>` implémente `Deref<Target = String>`, donc
        // `p.as_str()` passe par le `Deref`. On ne peut pas utiliser
        // `Zeroizing::as_str` (méthode d'association inexistante).
        let pass_ref = self.passphrase.as_deref().map(|p| p.as_str());
        self.mnemonic.to_seed(pass_ref)
    }
}

impl std::fmt::Debug for WalletV3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletV3")
            .field("mnemonic", &"<redacted>")
            .field("passphrase_used", &self.passphrase_used())
            .finish()
    }
}

fn map_hd_err(e: HdError) -> WalletError {
    WalletError::Usage(format!("HD derivation: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mnemonic connue (vecteur BIP-39, entropie zéro).
    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn sango_coin_type_devnet() {
        assert_eq!(sango_coin_type(Network::Devnet).unwrap(), 100_001);
    }

    #[test]
    fn sango_coin_type_testnet() {
        assert_eq!(sango_coin_type(Network::Testnet).unwrap(), 100_001);
    }

    #[test]
    fn sango_coin_type_mainnet_refused() {
        let err = sango_coin_type(Network::Mainnet).unwrap_err();
        assert!(matches!(err, WalletError::Usage(_)));
    }

    #[test]
    fn sango_hd_path_format() {
        let p = sango_hd_path(Network::Devnet, 0).unwrap();
        assert_eq!(p.to_string(), "m/44'/100001'/0'/0'/0'");
    }

    #[test]
    fn evm_hd_path_format() {
        let p = evm_hd_path(0);
        assert_eq!(p.to_string(), "m/44'/60'/0'/0/0");
    }

    #[test]
    fn wallet_from_mnemonic_is_deterministic() {
        let w1 = WalletV3::from_mnemonic_str(TEST_MNEMONIC, None).unwrap();
        let w2 = WalletV3::from_mnemonic_str(TEST_MNEMONIC, None).unwrap();
        let kp1 = w1.sango_keypair(Network::Devnet, 0).unwrap();
        let kp2 = w2.sango_keypair(Network::Devnet, 0).unwrap();
        assert_eq!(kp1.public_key(), kp2.public_key());
    }

    #[test]
    fn wallet_sango_keypair_stable() {
        let w = WalletV3::from_mnemonic_str(TEST_MNEMONIC, None).unwrap();
        let kp = w.sango_keypair(Network::Devnet, 0).unwrap();
        let kp2 = w.sango_keypair(Network::Devnet, 0).unwrap();
        assert_eq!(kp.public_key(), kp2.public_key());
    }

    #[test]
    fn wallet_evm_keypair_stable() {
        let w = WalletV3::from_mnemonic_str(TEST_MNEMONIC, None).unwrap();
        let kp = w.evm_keypair(0).unwrap();
        let kp2 = w.evm_keypair(0).unwrap();
        assert_eq!(kp.address(), kp2.address());
    }

    #[test]
    fn wallet_sango_and_evm_differ() {
        let w = WalletV3::from_mnemonic_str(TEST_MNEMONIC, None).unwrap();
        let sango_addr = sango_crypto::derive_native_address(
            &w.sango_keypair(Network::Devnet, 0).unwrap().public_key(),
        );
        let evm_addr = w.evm_keypair(0).unwrap().address();
        // Les deux adresses sont 20 bytes mais **distinctes** (chemins
        // HD différents).
        assert_ne!(sango_addr.as_bytes(), evm_addr.as_bytes());
    }

    #[test]
    fn account_index_changes_key() {
        let w = WalletV3::from_mnemonic_str(TEST_MNEMONIC, None).unwrap();
        let kp0 = w.sango_keypair(Network::Devnet, 0).unwrap();
        let kp1 = w.sango_keypair(Network::Devnet, 1).unwrap();
        assert_ne!(kp0.public_key(), kp1.public_key());
    }

    #[test]
    fn bip39_passphrase_changes_key() {
        let w_none = WalletV3::from_mnemonic_str(TEST_MNEMONIC, None).unwrap();
        let w_pass = WalletV3::from_mnemonic_str(TEST_MNEMONIC, Some("TREZOR".into())).unwrap();
        assert_ne!(
            w_none
                .sango_keypair(Network::Devnet, 0)
                .unwrap()
                .public_key(),
            w_pass
                .sango_keypair(Network::Devnet, 0)
                .unwrap()
                .public_key()
        );
    }

    #[test]
    fn passphrase_used_flag() {
        let w_none = WalletV3::from_mnemonic_str(TEST_MNEMONIC, None).unwrap();
        assert!(!w_none.passphrase_used());
        let w_empty = WalletV3::from_mnemonic_str(TEST_MNEMONIC, Some(String::new())).unwrap();
        assert!(!w_empty.passphrase_used());
        let w = WalletV3::from_mnemonic_str(TEST_MNEMONIC, Some("x".into())).unwrap();
        assert!(w.passphrase_used());
    }

    #[test]
    fn debug_does_not_leak() {
        let w = WalletV3::from_mnemonic_str(TEST_MNEMONIC, Some("secret".into())).unwrap();
        let s = format!("{w:?}");
        assert!(s.contains("redacted"));
        assert!(!s.contains("abandon"));
        assert!(!s.contains("secret"));
    }

    #[test]
    fn mainnet_sango_keypair_fails() {
        let w = WalletV3::from_mnemonic_str(TEST_MNEMONIC, None).unwrap();
        let err = w.sango_keypair(Network::Mainnet, 0).unwrap_err();
        assert!(matches!(err, WalletError::Usage(_)));
    }
}
