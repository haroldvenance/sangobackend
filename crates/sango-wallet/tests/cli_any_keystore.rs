//! Test d'intégration CLI : exerce le **binaire** `sango-wallet` sur des
//! keyfiles V1 et V3.
//!
//! ## Portée
//!
//! Seules les commandes **non-interactives** sont testées :
//! `address`, `keyfile-info`, `export-mnemonic`.
//!
//! Les commandes `new --bip39` et `import` nécessitent un TTY (prompts
//! `rpassword`) et sont couvertes en unitaire + golden V4A/V6.
//!
//! ## KDF password
//!
//! Fourni via `$SANGO_WALLET_PASSPHRASE` (comportement W4.c).
//!
//! ## Ce que ces tests verrouillent
//!
//! 1. Le binaire compile et s'exécute.
//! 2. `AnyKeyFile::load` détecte correctement V1 vs V3.
//! 3. `--account` est accepté sur V3, refusé sur V1 avec un message
//!    stable.
//! 4. `export-mnemonic` ne fonctionne que sur V3.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Mnemonic de référence (vecteur BIP-39 officiel, entropie = 0x00).
const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// Mot de passe KDF pour les keyfiles V3 de test.
const KDF_PASSWORD: &str = "test-kdf-password";

/// Chemin absolu vers le binaire `sango-wallet` (injecté par Cargo).
fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_sango-wallet")
}

/// Crée un keyfile V1 en clair dans `dir`.
fn create_v1(dir: &Path) -> PathBuf {
    let path = dir.join("wallet-v1.json");
    let _ = sango_wallet::KeyFile::create(&path).expect("create V1");
    path
}

/// Crée un keyfile V3 chiffré avec mnemonic fixe.
fn create_v3(dir: &Path) -> PathBuf {
    let path = dir.join("wallet-v3.json");
    let _ = sango_wallet::KeyFileV3::import(&path, TEST_MNEMONIC, None, KDF_PASSWORD.as_bytes())
        .expect("create V3");
    path
}

/// Lance le binaire avec `$SANGO_WALLET_PASSPHRASE` défini.
fn run(keyfile: &Path, args: &[&str]) -> Output {
    Command::new(bin())
        .env("SANGO_WALLET_PASSPHRASE", KDF_PASSWORD)
        .arg("--keyfile")
        .arg(keyfile)
        .args(args)
        .output()
        .expect("spawn sango-wallet")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

// --- V3 ---------------------------------------------------------------

#[test]
fn cli_v3_address_account_0() {
    let dir = tempfile::tempdir().unwrap();
    let kf = create_v3(dir.path());
    let out = run(&kf, &["address"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));

    let s = stdout(&out);
    let s = s.trim();
    assert!(s.starts_with("0x"), "got: {s:?}");
    assert_eq!(s.len(), 42, "expected 0x + 40 hex, got {} chars", s.len());
}

#[test]
fn cli_v3_address_account_1_differs() {
    let dir = tempfile::tempdir().unwrap();
    let kf = create_v3(dir.path());

    let a0 = stdout(&run(&kf, &["address"]));
    let a1 = stdout(&run(&kf, &["address", "--account", "1"]));

    assert_ne!(a0, a1, "account 0 and account 1 must differ on V3");
}

#[test]
fn cli_v3_keyfile_info_shows_v3_bip39() {
    let dir = tempfile::tempdir().unwrap();
    let kf = create_v3(dir.path());
    let out = run(&kf, &["keyfile-info"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));

    let s = stdout(&out);
    assert!(s.contains("V3"), "got: {s}");
    assert!(s.contains("BIP-39"), "got: {s}");
}

#[test]
fn cli_v3_export_mnemonic_returns_mnemonic() {
    let dir = tempfile::tempdir().unwrap();
    let kf = create_v3(dir.path());
    let out = run(&kf, &["export-mnemonic"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));

    assert_eq!(stdout(&out).trim(), TEST_MNEMONIC);
}

#[test]
fn cli_v3_pubkey() {
    let dir = tempfile::tempdir().unwrap();
    let kf = create_v3(dir.path());
    let out = run(&kf, &["pubkey"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));

    let s = stdout(&out);
    let s = s.trim();
    assert!(s.starts_with("0x"), "got: {s:?}");
    assert_eq!(s.len(), 66, "expected 0x + 64 hex, got {} chars", s.len());
}

// --- V1 ---------------------------------------------------------------

#[test]
fn cli_v1_address_account_0() {
    let dir = tempfile::tempdir().unwrap();
    let kf = create_v1(dir.path());
    let out = run(&kf, &["address"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));

    let s = stdout(&out);
    assert_eq!(s.trim().len(), 42);
}

#[test]
fn cli_v1_rejects_account_gt_0() {
    let dir = tempfile::tempdir().unwrap();
    let kf = create_v1(dir.path());
    let out = run(&kf, &["address", "--account", "1"]);

    assert!(!out.status.success(), "V1 must reject --account > 0");
    let e = stderr(&out);
    assert!(
        e.contains("single account"),
        "expected error about single account, got: {e}"
    );
}

#[test]
fn cli_v1_export_mnemonic_fails() {
    let dir = tempfile::tempdir().unwrap();
    let kf = create_v1(dir.path());
    let out = run(&kf, &["export-mnemonic"]);

    assert!(!out.status.success(), "V1 has no mnemonic");
    let e = stderr(&out);
    assert!(e.contains("V3"), "expected error mentioning V3, got: {e}");
}

// --- V1 ≠ V3 ----------------------------------------------------------

#[test]
fn cli_v1_and_v3_produce_different_addresses() {
    // V1 utilise une seed aléatoire ; V3 dérive depuis la mnemonic
    // de test. Les adresses doivent différer.
    let dir = tempfile::tempdir().unwrap();
    let v1 = create_v1(dir.path());
    let v3 = create_v3(dir.path());

    let a1 = stdout(&run(&v1, &["address"]));
    let a3 = stdout(&run(&v3, &["address"]));
    assert_ne!(a1, a3);
}
