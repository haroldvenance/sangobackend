//! Point d'entrée du binaire `sango-wallet`.

use std::process::ExitCode;

use sango_primitives::{Amount, NativeAddress};
use sango_types::TxKind;
use sango_wallet::cli::{parse_args, parse_flags, require_flag, HELP};
use sango_wallet::commands::{
    fetch_account, fetch_chain_id, format_base_units, parse_sango_decimal, send_transaction,
    TxParams,
};
use sango_wallet::keystore::KeyFile;
use sango_wallet::rpc_client::RpcClient;
use sango_wallet::WalletError;

const DEFAULT_RPC: &str = "127.0.0.1:8545";
const DEFAULT_MAX_FEE: u128 = 1_000_000; // 0.1 SANGO par gas max
const DEFAULT_PRIORITY_FEE: u128 = 0;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            if matches!(e, WalletError::Usage(_)) {
                eprintln!("\n{HELP}");
            }
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), WalletError> {
    let (opts, cmd, rest) = parse_args(args)?;
    let rpc_endpoint: &str = opts.rpc.as_deref().unwrap_or(DEFAULT_RPC);
    let keyfile_path = match opts.keyfile {
        Some(p) => std::path::PathBuf::from(p),
        None => KeyFile::default_path()?,
    };
    let kf_path = keyfile_path.as_path();

    match cmd.as_str() {
        "new" => cmd_new(kf_path),
        "address" => cmd_address(kf_path),
        "balance" => cmd_balance(rpc_endpoint, kf_path, &rest),
        "nonce" => cmd_nonce(rpc_endpoint, kf_path, &rest),
        "info" => cmd_info(rpc_endpoint),
        "send" => cmd_send(rpc_endpoint, kf_path, &rest),
        "stake" => cmd_stake(rpc_endpoint, kf_path, &rest),
        "unstake" => cmd_unstake(rpc_endpoint, kf_path, &rest),
        "delegate" => cmd_delegate(rpc_endpoint, kf_path, &rest),
        "undelegate" => cmd_undelegate(rpc_endpoint, kf_path, &rest),
        "claim" => cmd_claim(rpc_endpoint, kf_path, &rest),
        "register-validator" => cmd_register(rpc_endpoint, kf_path, &rest),
        "update-commission" => cmd_update_commission(rpc_endpoint, kf_path, &rest),
        "unjail" => cmd_unjail(rpc_endpoint, kf_path, &rest),
        other => Err(WalletError::Usage(format!("unknown command: {other}"))),
    }
}

// --- Commandes -------------------------------------------------------------

fn cmd_new(keyfile_path: &std::path::Path) -> Result<(), WalletError> {
    let kf = KeyFile::create(keyfile_path)?;
    println!("✓ Keyfile créé : {}", keyfile_path.display());
    println!("  Adresse : 0x{}", kf.address_hex);
    println!("  ⚠ Sauvegardez ce fichier — sans lui, vos fonds sont perdus.");
    Ok(())
}

fn cmd_address(keyfile_path: &std::path::Path) -> Result<(), WalletError> {
    let kf = KeyFile::load(keyfile_path)?;
    println!("0x{}", kf.address_hex);
    Ok(())
}

fn cmd_balance(
    rpc_endpoint: &str,
    keyfile_path: &std::path::Path,
    args: &[String],
) -> Result<(), WalletError> {
    let addr = resolve_address(keyfile_path, args)?;
    let rpc = RpcClient::new(rpc_endpoint);
    let (_, balance) = fetch_account(&rpc, &addr)?;
    println!(
        "{} base units ({} SANGO)",
        balance,
        format_base_units(balance)
    );
    Ok(())
}

fn cmd_nonce(
    rpc_endpoint: &str,
    keyfile_path: &std::path::Path,
    args: &[String],
) -> Result<(), WalletError> {
    let addr = resolve_address(keyfile_path, args)?;
    let rpc = RpcClient::new(rpc_endpoint);
    let (nonce, _) = fetch_account(&rpc, &addr)?;
    println!("{nonce}");
    Ok(())
}

fn cmd_info(rpc_endpoint: &str) -> Result<(), WalletError> {
    let rpc = RpcClient::new(rpc_endpoint);
    let info = rpc.call("sango_chainInfo", serde_json::json!([]))?;
    println!("{}", serde_json::to_string_pretty(&info)?);
    Ok(())
}

fn cmd_send(
    rpc_endpoint: &str,
    keyfile_path: &std::path::Path,
    args: &[String],
) -> Result<(), WalletError> {
    let flags = parse_flags(args)?;
    let to = parse_address_arg(&require_flag(&flags, "to")?)?;
    let amount = parse_sango_decimal(&require_flag(&flags, "amount")?)?;
    submit_tx(
        rpc_endpoint,
        keyfile_path,
        TxParams {
            chain_id: Default::default(),
            nonce: 0,
            gas_limit: 21_000,
            max_fee: DEFAULT_MAX_FEE,
            priority_fee: DEFAULT_PRIORITY_FEE,
            value: Amount::from_base_units(amount),
            tx_kind: TxKind::Transfer,
            recipient: Some(to),
            data: Vec::new(),
        },
    )
}

fn cmd_stake(
    rpc_endpoint: &str,
    keyfile_path: &std::path::Path,
    args: &[String],
) -> Result<(), WalletError> {
    let flags = parse_flags(args)?;
    let amount = parse_sango_decimal(&require_flag(&flags, "amount")?)?;
    submit_tx(
        rpc_endpoint,
        keyfile_path,
        TxParams {
            chain_id: Default::default(),
            nonce: 0,
            gas_limit: 50_000,
            max_fee: DEFAULT_MAX_FEE,
            priority_fee: DEFAULT_PRIORITY_FEE,
            value: Amount::from_base_units(amount),
            tx_kind: TxKind::Bond,
            recipient: None,
            data: Vec::new(),
        },
    )
}

fn cmd_unstake(
    rpc_endpoint: &str,
    keyfile_path: &std::path::Path,
    args: &[String],
) -> Result<(), WalletError> {
    let flags = parse_flags(args)?;
    let amount = parse_sango_decimal(&require_flag(&flags, "amount")?)?;
    submit_tx(
        rpc_endpoint,
        keyfile_path,
        TxParams {
            chain_id: Default::default(),
            nonce: 0,
            gas_limit: 50_000,
            max_fee: DEFAULT_MAX_FEE,
            priority_fee: DEFAULT_PRIORITY_FEE,
            value: Amount::from_base_units(amount),
            tx_kind: TxKind::Unbond,
            recipient: None,
            data: Vec::new(),
        },
    )
}

fn cmd_delegate(
    rpc_endpoint: &str,
    keyfile_path: &std::path::Path,
    args: &[String],
) -> Result<(), WalletError> {
    let flags = parse_flags(args)?;
    let validator = parse_address_arg(&require_flag(&flags, "validator")?)?;
    let amount = parse_sango_decimal(&require_flag(&flags, "amount")?)?;
    submit_tx(
        rpc_endpoint,
        keyfile_path,
        TxParams {
            chain_id: Default::default(),
            nonce: 0,
            gas_limit: 80_000,
            max_fee: DEFAULT_MAX_FEE,
            priority_fee: DEFAULT_PRIORITY_FEE,
            value: Amount::from_base_units(amount),
            tx_kind: TxKind::Delegate,
            recipient: Some(validator),
            data: Vec::new(),
        },
    )
}

fn cmd_undelegate(
    rpc_endpoint: &str,
    keyfile_path: &std::path::Path,
    args: &[String],
) -> Result<(), WalletError> {
    let flags = parse_flags(args)?;
    let validator = parse_address_arg(&require_flag(&flags, "validator")?)?;
    let amount = parse_sango_decimal(&require_flag(&flags, "amount")?)?;
    submit_tx(
        rpc_endpoint,
        keyfile_path,
        TxParams {
            chain_id: Default::default(),
            nonce: 0,
            gas_limit: 80_000,
            max_fee: DEFAULT_MAX_FEE,
            priority_fee: DEFAULT_PRIORITY_FEE,
            value: Amount::from_base_units(amount),
            tx_kind: TxKind::Undelegate,
            recipient: Some(validator),
            data: Vec::new(),
        },
    )
}

fn cmd_claim(
    rpc_endpoint: &str,
    keyfile_path: &std::path::Path,
    args: &[String],
) -> Result<(), WalletError> {
    let flags = parse_flags(args)?;
    let validator = parse_address_arg(&require_flag(&flags, "validator")?)?;
    submit_tx(
        rpc_endpoint,
        keyfile_path,
        TxParams {
            chain_id: Default::default(),
            nonce: 0,
            gas_limit: 40_000,
            max_fee: DEFAULT_MAX_FEE,
            priority_fee: DEFAULT_PRIORITY_FEE,
            value: Amount::ZERO,
            tx_kind: TxKind::ClaimRewards,
            recipient: Some(validator),
            data: Vec::new(),
        },
    )
}

fn cmd_register(
    rpc_endpoint: &str,
    keyfile_path: &std::path::Path,
    args: &[String],
) -> Result<(), WalletError> {
    let flags = parse_flags(args)?;
    let commission_bps: u32 = require_flag(&flags, "commission-bps")?
        .parse()
        .map_err(|e| WalletError::InvalidAmount(format!("commission-bps: {e}")))?;
    let amount = parse_sango_decimal(&require_flag(&flags, "amount")?)?;
    let mut data = Vec::with_capacity(4);
    data.extend_from_slice(&commission_bps.to_be_bytes());
    submit_tx(
        rpc_endpoint,
        keyfile_path,
        TxParams {
            chain_id: Default::default(),
            nonce: 0,
            gas_limit: 200_000,
            max_fee: DEFAULT_MAX_FEE,
            priority_fee: DEFAULT_PRIORITY_FEE,
            value: Amount::from_base_units(amount),
            tx_kind: TxKind::RegisterValidator,
            recipient: None,
            data,
        },
    )
}

fn cmd_update_commission(
    rpc_endpoint: &str,
    keyfile_path: &std::path::Path,
    args: &[String],
) -> Result<(), WalletError> {
    let flags = parse_flags(args)?;
    let new_bps: u32 = require_flag(&flags, "new-bps")?
        .parse()
        .map_err(|e| WalletError::InvalidAmount(format!("new-bps: {e}")))?;
    let mut data = Vec::with_capacity(4);
    data.extend_from_slice(&new_bps.to_be_bytes());
    submit_tx(
        rpc_endpoint,
        keyfile_path,
        TxParams {
            chain_id: Default::default(),
            nonce: 0,
            gas_limit: 30_000,
            max_fee: DEFAULT_MAX_FEE,
            priority_fee: DEFAULT_PRIORITY_FEE,
            value: Amount::ZERO,
            tx_kind: TxKind::UpdateCommission,
            recipient: None,
            data,
        },
    )
}

fn cmd_unjail(
    rpc_endpoint: &str,
    keyfile_path: &std::path::Path,
    args: &[String],
) -> Result<(), WalletError> {
    let _flags = parse_flags(args)?;
    submit_tx(
        rpc_endpoint,
        keyfile_path,
        TxParams {
            chain_id: Default::default(),
            nonce: 0,
            gas_limit: 30_000,
            max_fee: DEFAULT_MAX_FEE,
            priority_fee: DEFAULT_PRIORITY_FEE,
            value: Amount::ZERO,
            tx_kind: TxKind::Unjail,
            recipient: None,
            data: Vec::new(),
        },
    )
}

// --- Helpers ---------------------------------------------------------------

/// Résout une adresse depuis un argument optionnel, ou charge le keyfile.
fn resolve_address(
    keyfile_path: &std::path::Path,
    args: &[String],
) -> Result<NativeAddress, WalletError> {
    if let Some(arg) = args.first() {
        if !arg.starts_with("--") {
            return parse_address_arg(arg);
        }
    }
    let kf = KeyFile::load(keyfile_path)?;
    kf.address()
}

/// Parse `0x...` (ou sans préfixe) en `NativeAddress`.
fn parse_address_arg(s: &str) -> Result<NativeAddress, WalletError> {
    NativeAddress::from_hex(s).map_err(|e| WalletError::InvalidAddress(format!("{s}: {e}")))
}

/// Soumet une transaction : remplit chain_id + nonce, signe, envoie.
fn submit_tx(
    rpc_endpoint: &str,
    keyfile_path: &std::path::Path,
    mut params: TxParams,
) -> Result<(), WalletError> {
    let kf = KeyFile::load(keyfile_path)?;
    let rpc = RpcClient::new(rpc_endpoint);

    // Récupérer chain_id et nonce courants.
    params.chain_id = fetch_chain_id(&rpc)?;
    let addr = kf.address()?;
    let (nonce, _) = fetch_account(&rpc, &addr)?;
    params.nonce = nonce;

    // Signer et envoyer.
    let tx = params.build_and_sign(&kf)?;
    let tx_hash = send_transaction(&rpc, &tx)?;
    println!("✓ Transaction envoyée");
    println!("  Hash : {tx_hash}");
    Ok(())
}
