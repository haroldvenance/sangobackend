//! Golden vectors V4A — mnemonic BIP-39 → adresses Sango + EVM.
//!
//! ## Source
//!
//! Mnemonic de référence BIP-39 (entropie zéro, 12 mots). Les adresses
//! attendues sont **figées byte-à-byte** une fois calculées, pour
//! garantir la compatibilité Rust ↔ TypeScript ↔ MetaMask ↔ Phantom.
//!
//! ## Remplissage
//!
//! ```text
//! cargo test -p sango-wallet --test wallet_v3_golden print_golden -- --nocapture
//! ```
//!
//! Copier les valeurs affichées dans les constantes ci-dessous, puis
//! relancer `cargo test`.
//!
//! ## Contrainte
//!
//! Ces constantes sont **normatives**. Une divergence = hard fork de
//! wallet, à documenter et coordonner avec le frontend.

use sango_crypto::bech32m::{encode_native_address, Network};
use sango_crypto::{derive_native_address, evm_checksum_hex};
use sango_wallet::WalletV3;

/// Mnemonic de référence (vecteur BIP-39 officiel, entropie = 0x00).
const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// **Second vecteur indépendant** : mnemonic par défaut Hardhat / Anvil
/// / Foundry / ethers.js.
///
/// ## Pourquoi
///
/// V4A (vecteur BIP-39 officiel `abandon … about`) valide notre
/// dérivation sur une mnemonic de référence. Ce second vecteur, sur
/// une mnemonic **différente**, valide qu'on n'est pas
/// accidentellement d'accord avec MetaMask sur une seule entrée.
///
/// ## Source de vérité
///
/// L'adresse EVM attendue (`0xf39Fd6e5…`) est **publiquement vérifiable** :
/// elle apparaît dans la sortie par défaut de Hardhat, Anvil, Foundry et
/// dans la doc ethers.js. C'est l'adresse de référence des tutoriels
/// Ethereum pour `m/44'/60'/0'/0/0`.
const HARDHAT_MNEMONIC: &str = "test test test test test test test test test test test junk";

/// Adresse EVM attendue pour [`HARDHAT_MNEMONIC`] à l'index 0.
///
/// Valeur **publiquement connue** (Hardhat / Anvil / Foundry).
const HARDHAT_EVM_ADDRESS: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

/// Adresse Sango native devnet à l'index 0 (à remplir après `print_golden_2`).
const HARDHAT_SANGO_ADDRESS_DEVNET: &str = "tsango1882fg6lw3swwygtvvn47hgjnacxz9rr55agjlz";

// --- ⚠️ À remplir après la première exécution -------------------------------

/// Adresse Sango native (bech32m, devnet) à l'index 0.
const EXPECTED_SANGO_ADDRESS_DEVNET: &str = "tsango13ujlkt9hdx7spcausd8a7wd0n63spscumvc32s";

/// Adresse Sango native (bech32m, mainnet) à l'index 0.
///
/// **Note** : dérivable seulement après décision du coin type mainnet.
/// En attendant, laissé en `PLACEHOLDER` et le test se skip.
///
/// Le jour où le coin type mainnet est figé (SLIP-0044 ou collégial),
/// remplacer par la valeur affichée par `print_golden`.
const EXPECTED_SANGO_ADDRESS_MAINNET: &str = "PLACEHOLDER";

/// Adresse EVM (hex `0x…`) à l'index 0.
const EXPECTED_EVM_ADDRESS: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";

// --- Helpers ----------------------------------------------------------------

fn compute_sango_address_devnet() -> String {
    let w = WalletV3::from_mnemonic_str(TEST_MNEMONIC, None).unwrap();
    let kp = w.sango_keypair(Network::Devnet, 0).unwrap();
    let addr = derive_native_address(&kp.public_key());
    encode_native_address(addr, Network::Devnet)
}

fn compute_sango_address_mainnet() -> Option<String> {
    let w = WalletV3::from_mnemonic_str(TEST_MNEMONIC, None).unwrap();
    match w.sango_keypair(Network::Mainnet, 0) {
        Ok(kp) => {
            let addr = derive_native_address(&kp.public_key());
            Some(encode_native_address(addr, Network::Mainnet))
        }
        Err(_) => None,
    }
}

fn compute_evm_address() -> String {
    let w = WalletV3::from_mnemonic_str(TEST_MNEMONIC, None).unwrap();
    let kp = w.evm_keypair(0).unwrap();
    evm_checksum_hex(&kp.address())
}

fn compute_hardhat_evm_address() -> String {
    let w = WalletV3::from_mnemonic_str(HARDHAT_MNEMONIC, None).unwrap();
    let kp = w.evm_keypair(0).unwrap();
    evm_checksum_hex(&kp.address())
}

fn compute_hardhat_sango_address_devnet() -> String {
    let w = WalletV3::from_mnemonic_str(HARDHAT_MNEMONIC, None).unwrap();
    let kp = w.sango_keypair(Network::Devnet, 0).unwrap();
    let addr = derive_native_address(&kp.public_key());
    encode_native_address(addr, Network::Devnet)
}

// --- Print --------------------------------------------------------------

#[test]
fn print_golden() {
    let sango_devnet = compute_sango_address_devnet();
    let sango_mainnet = compute_sango_address_mainnet();
    let evm = compute_evm_address();

    println!("\n===== V4A GOLDEN VECTORS =====");
    println!("Mnemonic : {TEST_MNEMONIC}");
    println!();
    println!("Chemin Sango devnet : m/44'/100001'/0'/0'/0'");
    println!("  EXPECTED_SANGO_ADDRESS_DEVNET = \"{sango_devnet}\"");
    println!();
    match sango_mainnet {
        Some(s) => {
            println!("Chemin Sango mainnet : m/44'/<TBD>'/0'/0'/0'");
            println!("  EXPECTED_SANGO_ADDRESS_MAINNET = \"{s}\"");
        }
        None => {
            println!("Chemin Sango mainnet : refusé (coin type non figé)");
            println!("  EXPECTED_SANGO_ADDRESS_MAINNET = \"PLACEHOLDER\"");
        }
    }
    println!();
    println!("Chemin EVM : m/44'/60'/0'/0/0");
    println!("  EXPECTED_EVM_ADDRESS = \"{evm}\"");
    println!();
    println!("===== FIN =====\n");
}

// --- Golden -----------------------------------------------------------

#[test]
fn golden_v4a_sango_address_devnet() {
    if EXPECTED_SANGO_ADDRESS_DEVNET == "PLACEHOLDER" {
        eprintln!(
            "\n⚠️  EXPECTED_SANGO_ADDRESS_DEVNET non rempli.\\
             \n   Lance : cargo test -p sango-wallet --test wallet_v3_golden print_golden -- --nocapture\\n"
        );
        return;
    }
    assert_eq!(
        compute_sango_address_devnet(),
        EXPECTED_SANGO_ADDRESS_DEVNET
    );
}

#[test]
fn golden_v4a_sango_address_mainnet_optional() {
    if EXPECTED_SANGO_ADDRESS_MAINNET == "PLACEHOLDER" {
        assert!(
            compute_sango_address_mainnet().is_none(),
            "mainnet should be refused while coin type is TBD"
        );
        return;
    }
    assert_eq!(
        compute_sango_address_mainnet().as_deref(),
        Some(EXPECTED_SANGO_ADDRESS_MAINNET)
    );
}

#[test]
fn golden_v4a_evm_address() {
    if EXPECTED_EVM_ADDRESS == "PLACEHOLDER" {
        eprintln!(
            "\n⚠️  EXPECTED_EVM_ADDRESS non rempli.\\
             \n   Lance : cargo test -p sango-wallet --test wallet_v3_golden print_golden -- --nocapture\\n"
        );
        return;
    }
    assert_eq!(compute_evm_address(), EXPECTED_EVM_ADDRESS);
}

// --- Second vecteur golden : Hardhat / Anvil -------------------------

#[test]
fn print_golden_2() {
    let evm = compute_hardhat_evm_address();
    let sango = compute_hardhat_sango_address_devnet();

    println!("\n===== V4B GOLDEN VECTORS (Hardhat) =====");
    println!("Mnemonic : {HARDHAT_MNEMONIC}");
    println!();
    println!("Chemin EVM : m/44'/60'/0'/0/0");
    println!("  (publiquement connu : Hardhat / Anvil / Foundry)");
    println!("  EXPECTED (assertif) = {HARDHAT_EVM_ADDRESS}");
    println!("  GOT                 = {evm}");
    println!();
    println!("Chemin Sango devnet : m/44'/100001'/0'/0'/0'");
    println!("  HARDHAT_SANGO_ADDRESS_DEVNET = \"{sango}\"");
    println!();
    println!("===== FIN =====\n");
}

/// Assertif : l'adresse EVM dérivée doit matcher Hardhat / Anvil.
///
/// Ce test échoue si notre implémentation BIP-32 diverge de la
/// référence Ethereum, indépendamment de la mnemonic choisie.
#[test]
fn golden_v4b_evm_address_hardhat() {
    assert_eq!(
        compute_hardhat_evm_address(),
        HARDHAT_EVM_ADDRESS,
        "V4B EVM derivation does not match Hardhat/Anvil reference"
    );
}

/// Assertif (une fois rempli) : adresse Sango native du 2e vecteur.
#[test]
fn golden_v4b_sango_address_devnet() {
    if HARDHAT_SANGO_ADDRESS_DEVNET == "PLACEHOLDER" {
        eprintln!(
            "\n⚠️  HARDHAT_SANGO_ADDRESS_DEVNET non rempli.\
             \n   Lance : cargo test -p sango-wallet --test wallet_v3_golden print_golden_2 -- --nocapture\n"
        );
        return;
    }
    assert_eq!(
        compute_hardhat_sango_address_devnet(),
        HARDHAT_SANGO_ADDRESS_DEVNET
    );
}

// --- Propriétés (indépendantes des golden) ----------------------------

#[test]
fn determinism_sango_address() {
    assert_eq!(
        compute_sango_address_devnet(),
        compute_sango_address_devnet()
    );
}

#[test]
fn determinism_evm_address() {
    assert_eq!(compute_evm_address(), compute_evm_address());
}

#[test]
fn sango_and_evm_addresses_differ() {
    assert_ne!(compute_sango_address_devnet(), compute_evm_address());
}

#[test]
fn passphrase_bip39_changes_addresses() {
    let w_none = WalletV3::from_mnemonic_str(TEST_MNEMONIC, None).unwrap();
    let w_pass = WalletV3::from_mnemonic_str(TEST_MNEMONIC, Some("TREZOR".into())).unwrap();

    let a1 = w_none
        .sango_keypair(Network::Devnet, 0)
        .unwrap()
        .public_key();
    let a2 = w_pass
        .sango_keypair(Network::Devnet, 0)
        .unwrap()
        .public_key();
    assert_ne!(a1, a2);
}

#[test]
fn account_index_changes_addresses() {
    let w = WalletV3::from_mnemonic_str(TEST_MNEMONIC, None).unwrap();
    let k0 = w.sango_keypair(Network::Devnet, 0).unwrap();
    let k1 = w.sango_keypair(Network::Devnet, 1).unwrap();
    assert_ne!(k0.public_key(), k1.public_key());
}
