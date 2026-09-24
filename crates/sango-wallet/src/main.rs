//! Point d'entrée du binaire `sango-wallet`.

use std::process::ExitCode;

use sango_primitives::{Amount, EvmAddress, NativeAddress, U256};
use sango_types::TxKind;
use sango_wallet::cli::{optional_flag, parse_args, parse_flags, require_flag, HELP};
use sango_wallet::commands::{
    fetch_account, fetch_chain_id, format_base_units, parse_sango_decimal, send_transaction,
    TxParams,
};
use sango_wallet::evm::{EvmTxBuilder, FeeType};
use sango_wallet::keystore::KeyFile;
use sango_wallet::rpc_client::RpcClient;
use sango_wallet::WalletError;

const DEFAULT_RPC: &str = "127.0.0.1:8545";
const DEFAULT_MAX_FEE: u128 = 1_000_000;
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
        // --- Natif ---
        "new" => cmd_new(kf_path),
        "address" => cmd_address(kf_path),
        "pubkey" => cmd_pubkey(kf_path),
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

        // --- EVM ---
        "evm-new" => cmd_evm_new(kf_path),
        "evm-address" => cmd_evm_address(kf_path),
        "evm-balance" => cmd_evm_balance(rpc_endpoint, kf_path, &rest),
        "evm-nonce" => cmd_evm_nonce(rpc_endpoint, kf_path, &rest),
        "evm-call" => cmd_evm_call(rpc_endpoint, &rest),
        "evm-sign" => cmd_evm_sign(rpc_endpoint, kf_path, &rest),

        other => Err(WalletError::Usage(format!("unknown command: {other}"))),
    }
}

// --- Commandes natives (inchangées) ---------------------------------------

fn cmd_new(keyfile_path: &std::path::Path) -> Result<(), WalletError> {
    let kf = KeyFile::create(keyfile_path)?;
    println!("✓ Keyfile créé : {}", keyfile_path.display());
    println!("  Adresse native : 0x{}", kf.address_hex);
    println!("  ⚠ Sauvegardez ce fichier — sans lui, vos fonds sont perdus.");
    println!("  (Ajoutez une clé EVM avec `sango-wallet evm-new`.)");
    Ok(())
}

fn cmd_address(keyfile_path: &std::path::Path) -> Result<(), WalletError> {
    let kf = KeyFile::load(keyfile_path)?;
    println!("0x{}", kf.address_hex);
    Ok(())
}

fn cmd_pubkey(keyfile_path: &std::path::Path) -> Result<(), WalletError> {
    let kf = KeyFile::load(keyfile_path)?;
    println!("0x{}", kf.public_key_hex()?);
    Ok(())
}

fn cmd_balance(
    rpc_endpoint: &str,
    keyfile_path: &std::path::Path,
    args: &[String],
) -> Result<(), WalletError> {
    let addr = resolve_address(keyfile_path, args)?;
    let rpc = RpcClient::new(rpc_endpoint);
    let (_, balance, _) = fetch_account(&rpc, &addr)?;
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
    let (nonce, _, _) = fetch_account(&rpc, &addr)?;
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

// --- Commandes EVM ---------------------------------------------------------

fn cmd_evm_new(keyfile_path: &std::path::Path) -> Result<(), WalletError> {
    let mut kf = if keyfile_path.exists() {
        KeyFile::load(keyfile_path)?
    } else {
        KeyFile::create(keyfile_path)?
    };
    if kf.has_evm_key() {
        return Err(WalletError::InvalidKeyfile(
            "EVM key already present in keyfile".into(),
        ));
    }
    kf.attach_evm_key(keyfile_path)?;
    let addr = kf.evm_address()?;
    println!("✓ Clé EVM attachée au keyfile");
    println!("  Adresse EVM : 0x{}", addr.to_hex());
    Ok(())
}

fn cmd_evm_address(keyfile_path: &std::path::Path) -> Result<(), WalletError> {
    let kf = KeyFile::load(keyfile_path)?;
    let addr = kf.evm_address()?;
    println!("0x{}", addr.to_hex());
    Ok(())
}

fn cmd_evm_balance(
    rpc_endpoint: &str,
    keyfile_path: &std::path::Path,
    args: &[String],
) -> Result<(), WalletError> {
    let addr = resolve_evm_address(keyfile_path, args)?;
    let rpc = RpcClient::new(rpc_endpoint);
    let result = rpc.call(
        "eth_getBalance",
        serde_json::json!([format!("0x{}", addr.to_hex()), "latest"]),
    )?;
    let hex = result
        .as_str()
        .ok_or_else(|| WalletError::Rpc("eth_getBalance: expected hex string".into()))?;
    println!("{hex}");
    Ok(())
}

fn cmd_evm_nonce(
    rpc_endpoint: &str,
    keyfile_path: &std::path::Path,
    args: &[String],
) -> Result<(), WalletError> {
    let addr = resolve_evm_address(keyfile_path, args)?;
    let rpc = RpcClient::new(rpc_endpoint);
    let result = rpc.call(
        "eth_getTransactionCount",
        serde_json::json!([format!("0x{}", addr.to_hex()), "latest"]),
    )?;
    let hex = result
        .as_str()
        .ok_or_else(|| WalletError::Rpc("eth_getTransactionCount: expected hex".into()))?;
    println!("{hex}");
    Ok(())
}

fn cmd_evm_call(rpc_endpoint: &str, args: &[String]) -> Result<(), WalletError> {
    let flags = parse_flags(args)?;
    let to = require_flag(&flags, "to")?;
    let data = optional_flag(&flags, "data").unwrap_or("0x");
    let value = optional_flag(&flags, "value").unwrap_or("0x0");

    let rpc = RpcClient::new(rpc_endpoint);
    let result = rpc.call(
        "eth_call",
        serde_json::json!([
            {
                "to": to,
                "data": data,
                "value": value,
            },
            "latest"
        ]),
    )?;
    println!("{}", result.as_str().unwrap_or("0x"));
    Ok(())
}

fn cmd_evm_sign(
    rpc_endpoint: &str,
    keyfile_path: &std::path::Path,
    args: &[String],
) -> Result<(), WalletError> {
    let flags = parse_flags(args)?;
    let to_str = require_flag(&flags, "to")?;
    let to = EvmAddress::from_hex(&to_str)
        .map_err(|e| WalletError::InvalidAddress(format!("{to_str}: {e}")))?;
    let value = parse_u256_flag(&flags, "value").unwrap_or(U256::ZERO);

    let data = match optional_flag(&flags, "data") {
        Some(s) => hex::decode(s.strip_prefix("0x").unwrap_or(s))?,
        None => Vec::new(),
    };

    let kf = KeyFile::load(keyfile_path)?;
    let kp = kf.evm_keypair()?;
    let addr = kp.address();

    let rpc = RpcClient::new(rpc_endpoint);

    // Chain ID EVM.
    let chain_id_hex = rpc
        .call("eth_chainId", serde_json::json!([]))?
        .as_str()
        .ok_or_else(|| WalletError::Rpc("eth_chainId: expected string".into()))?
        .to_string();
    let chain_id = u64::from_str_radix(chain_id_hex.trim_start_matches("0x"), 16)
        .map_err(|e| WalletError::Rpc(format!("bad chainId: {e}")))?;

    // Nonce.
    let nonce_hex = rpc
        .call(
            "eth_getTransactionCount",
            serde_json::json!([format!("0x{}", addr.to_hex()), "latest"]),
        )?
        .as_str()
        .ok_or_else(|| WalletError::Rpc("nonce: expected string".into()))?
        .to_string();
    let nonce = u64::from_str_radix(nonce_hex.trim_start_matches("0x"), 16).unwrap_or(0);

    // Gas price (approximation depuis la base fee via eth_gasPrice).
    let gas_price_hex = rpc
        .call("eth_gasPrice", serde_json::json!([]))?
        .as_str()
        .ok_or_else(|| WalletError::Rpc("eth_gasPrice: expected string".into()))?
        .to_string();
    let gas_price_u128 =
        u128::from_str_radix(gas_price_hex.trim_start_matches("0x"), 16).unwrap_or(1);

    let gas_limit = match optional_flag(&flags, "gas") {
        Some(s) => s.parse::<u64>().unwrap_or(21_000),
        None => 21_000,
    };

    let fee = match optional_flag(&flags, "tx-type").unwrap_or("1559") {
        "legacy" => FeeType::Legacy {
            gas_price: U256::from(gas_price_u128),
        },
        "2930" => FeeType::Eip2930 {
            gas_price: U256::from(gas_price_u128),
        },
        _ => FeeType::Eip1559 {
            max_fee_per_gas: U256::from(gas_price_u128),
            max_priority_fee_per_gas: U256::from(1_000_000u64),
        },
    };

    let builder = EvmTxBuilder {
        chain_id,
        nonce,
        gas_limit,
        to: Some(to),
        value,
        data,
        access_list: Vec::new(),
        fee,
    };
    let tx = builder.sign(&kp)?;
    let raw = tx.encode_ethereum_typed();
    println!("0x{}", hex::encode(&raw));
    eprintln!(
        "(Signature produite localement. Broadcast via `eth_sendRawTransaction` non encore supporté — voir 4c.3.)"
    );
    Ok(())
}

// --- Helpers ---------------------------------------------------------------

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

fn resolve_evm_address(
    keyfile_path: &std::path::Path,
    args: &[String],
) -> Result<EvmAddress, WalletError> {
    if let Some(arg) = args.first() {
        if !arg.starts_with("--") {
            return EvmAddress::from_hex(arg)
                .map_err(|e| WalletError::InvalidAddress(format!("{arg}: {e}")));
        }
    }
    let kf = KeyFile::load(keyfile_path)?;
    kf.evm_address()
}

fn parse_address_arg(s: &str) -> Result<NativeAddress, WalletError> {
    NativeAddress::from_hex(s).map_err(|e| WalletError::InvalidAddress(format!("{s}: {e}")))
}

fn parse_u256_flag(flags: &[(String, String)], name: &str) -> Option<U256> {
    let s = optional_flag(flags, name)?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    let padded = if s.len() % 2 == 1 {
        format!("0{s}")
    } else {
        s.to_string()
    };
    let bytes = hex::decode(&padded).ok()?;
    if bytes.len() > 32 {
        return None;
    }
    let mut buf = [0u8; 32];
    buf[32 - bytes.len()..].copy_from_slice(&bytes);
    Some(U256::from_be_bytes::<32>(buf))
}

fn submit_tx(
    rpc_endpoint: &str,
    keyfile_path: &std::path::Path,
    mut params: TxParams,
) -> Result<(), WalletError> {
    let kf = KeyFile::load(keyfile_path)?;
    let rpc = RpcClient::new(rpc_endpoint);

    params.chain_id = fetch_chain_id(&rpc)?;
    let addr = kf.address()?;
    let (nonce, _, onchain_pk) = fetch_account(&rpc, &addr)?;
    params.nonce = nonce;

    let declare_pk = if onchain_pk.is_none() {
        Some(kf.public_key()?)
    } else {
        None
    };

    let tx = params.build_and_sign(&kf, declare_pk)?;
    let tx_hash = send_transaction(&rpc, &tx)?;
    println!("✓ Transaction envoyée");
    println!("  Hash : {tx_hash}");
    Ok(())
}
