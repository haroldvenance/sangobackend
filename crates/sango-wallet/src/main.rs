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
use sango_wallet::rpc_client::{RpcClient, TlsClientOptions, TrustMode};
use sango_wallet::WalletError;

const DEFAULT_RPC: &str = "127.0.0.1:8545";
const DEFAULT_MAX_FEE: u128 = 1_000_000;
const DEFAULT_PRIORITY_FEE: u128 = 0;

fn build_rpc_client(opts: &sango_wallet::cli::GlobalOpts) -> Result<RpcClient, WalletError> {
    let endpoint = opts.rpc.as_deref().unwrap_or(DEFAULT_RPC);

    if opts.rpc_tls_insecure {
        return RpcClient::new_with_tls(
            endpoint,
            TlsClientOptions {
                trust: TrustMode::AcceptAny,
                server_name: "localhost".to_string(),
            },
        );
    }
    if let Some(path) = &opts.rpc_tls_ca {
        let ca_der = std::fs::read(path)?;
        return RpcClient::new_with_tls(
            endpoint,
            TlsClientOptions {
                trust: TrustMode::CustomCa(ca_der),
                server_name: "localhost".to_string(),
            },
        );
    }
    Ok(RpcClient::new(endpoint))
}

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
    let keyfile_path = match &opts.keyfile {
        Some(p) => std::path::PathBuf::from(p),
        None => KeyFile::default_path()?,
    };
    let kf_path = keyfile_path.as_path();

    // Construire le client RPC une seule fois (HTTP ou HTTPS).
    let rpc = build_rpc_client(&opts)?;

    match cmd.as_str() {
        // --- Natif ---
        "new" => cmd_new(kf_path),
        "address" => cmd_address(kf_path),
        "pubkey" => cmd_pubkey(kf_path),
        "balance" => cmd_balance(&rpc, kf_path, &rest),
        "nonce" => cmd_nonce(&rpc, kf_path, &rest),
        "info" => cmd_info(&rpc),
        "history" => cmd_history(&rpc, kf_path, &rest),
        "send" => cmd_send(&rpc, kf_path, &rest),
        "stake" => cmd_stake(&rpc, kf_path, &rest),
        "unstake" => cmd_unstake(&rpc, kf_path, &rest),
        "delegate" => cmd_delegate(&rpc, kf_path, &rest),
        "undelegate" => cmd_undelegate(&rpc, kf_path, &rest),
        "claim" => cmd_claim(&rpc, kf_path, &rest),
        "register-validator" => cmd_register(&rpc, kf_path, &rest),
        "update-commission" => cmd_update_commission(&rpc, kf_path, &rest),
        "unjail" => cmd_unjail(&rpc, kf_path, &rest),

        // --- EVM ---
        "evm-new" => cmd_evm_new(kf_path),
        "evm-address" => cmd_evm_address(kf_path),
        "evm-balance" => cmd_evm_balance(&rpc, kf_path, &rest),
        "evm-nonce" => cmd_evm_nonce(&rpc, kf_path, &rest),
        "evm-call" => cmd_evm_call(&rpc, &rest),
        "evm-sign" => cmd_evm_sign(&rpc, kf_path, &rest),

        // --- Gestion du keyfile ---
        "keyfile-encrypt" => cmd_keyfile_encrypt(kf_path),
        "keyfile-decrypt" => cmd_keyfile_decrypt(kf_path),
        "keyfile-info" => cmd_keyfile_info(kf_path),

        other => Err(WalletError::Usage(format!("unknown command: {other}"))),
    }
}

// --- Commandes natives (inchangées) ---------------------------------------

fn cmd_new(keyfile_path: &std::path::Path) -> Result<(), WalletError> {
    let kf = KeyFile::create(keyfile_path)?;
    println!("✓ Keyfile créé : {}", keyfile_path.display());
    println!("  Adresse native : 0x{}", kf.address_hex);
    println!("  ⚠ Sauvegardez ce fichier — sans lui, vos fonds sont perdus.");
    println!();
    println!("  SÉCURITÉ : ce keyfile est en clair. Chiffrez-le avec :");
    println!(
        "    sango-wallet --keyfile {} keyfile-encrypt",
        keyfile_path.display()
    );
    println!("  (ou ajoutez une clé EVM avec `evm-new`.)");
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
    rpc: &RpcClient,
    keyfile_path: &std::path::Path,
    args: &[String],
) -> Result<(), WalletError> {
    let addr = resolve_address(keyfile_path, args)?;
    let (_, balance, _) = fetch_account(rpc, &addr)?;
    println!(
        "{} base units ({} SANGO)",
        balance,
        format_base_units(balance)
    );
    Ok(())
}

fn cmd_nonce(
    rpc: &RpcClient,
    keyfile_path: &std::path::Path,
    args: &[String],
) -> Result<(), WalletError> {
    let addr = resolve_address(keyfile_path, args)?;
    let (nonce, _, _) = fetch_account(rpc, &addr)?;
    println!("{nonce}");
    Ok(())
}

fn cmd_info(rpc: &RpcClient) -> Result<(), WalletError> {
    let info = rpc.call("sango_chainInfo", serde_json::json!([]))?;
    println!("{}", serde_json::to_string_pretty(&info)?);
    Ok(())
}

/// `history [ADDR] [--limit N] [--offset M]`
///
/// Liste les transactions **natives** émises par `ADDR` (défaut : adresse
/// du keyfile). Ordre décroissant par hauteur.
fn cmd_history(
    rpc: &RpcClient,
    keyfile_path: &std::path::Path,
    args: &[String],
) -> Result<(), WalletError> {
    let addr = resolve_address(keyfile_path, args)?;

    let mut limit: u32 = 20;
    let mut offset: u32 = 0;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--limit" => {
                limit = args
                    .get(i + 1)
                    .ok_or_else(|| WalletError::Usage("--limit needs a value".into()))?
                    .parse()
                    .map_err(|e| WalletError::Usage(format!("--limit: {e}")))?;
                i += 2;
            }
            "--offset" => {
                offset = args
                    .get(i + 1)
                    .ok_or_else(|| WalletError::Usage("--offset needs a value".into()))?
                    .parse()
                    .map_err(|e| WalletError::Usage(format!("--offset: {e}")))?;
                i += 2;
            }
            _ => i += 1,
        }
    }

    let result = rpc.call(
        "sango_getTransactionsByAddress",
        serde_json::json!([format!("0x{}", addr.to_hex()), limit, offset]),
    )?;

    let total = result.get("total").and_then(|v| v.as_u64()).unwrap_or(0);
    let items = result
        .get("items")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    println!(
        "Transactions de 0x{} — {} au total, {} affichée(s)",
        addr.to_hex(),
        total,
        items.len()
    );
    println!();

    if items.is_empty() {
        println!("  (aucune transaction)");
        return Ok(());
    }

    for (i, item) in items.iter().enumerate() {
        let hash = item.get("hash").and_then(|v| v.as_str()).unwrap_or("0x?");
        let height = item
            .get("blockHeight")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let tx_index = item.get("txIndex").and_then(|v| v.as_u64()).unwrap_or(0);
        let kind = item.get("kind").and_then(|v| v.as_str()).unwrap_or("?");
        let tx_kind = item
            .get("txKind")
            .and_then(|v| v.as_u64())
            .map(|v| format!("{v}"))
            .unwrap_or_else(|| "-".into());

        let short_hash = if hash.len() >= 12 {
            format!("{}…{}", &hash[..8], &hash[hash.len() - 4..])
        } else {
            hash.to_string()
        };

        println!(
            "  #{:<3} {}  bloc {:<6} idx {}  {}  txKind={}",
            offset + i as u32 + 1,
            short_hash,
            height,
            tx_index,
            kind,
            tx_kind,
        );
    }
    Ok(())
}

fn cmd_send(
    rpc: &RpcClient,
    keyfile_path: &std::path::Path,
    args: &[String],
) -> Result<(), WalletError> {
    let flags = parse_flags(args)?;
    let to = parse_address_arg(&require_flag(&flags, "to")?)?;
    let amount = parse_sango_decimal(&require_flag(&flags, "amount")?)?;
    submit_tx(
        rpc,
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
    rpc: &RpcClient,
    keyfile_path: &std::path::Path,
    args: &[String],
) -> Result<(), WalletError> {
    let flags = parse_flags(args)?;
    let amount = parse_sango_decimal(&require_flag(&flags, "amount")?)?;
    submit_tx(
        rpc,
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
    rpc: &RpcClient,
    keyfile_path: &std::path::Path,
    args: &[String],
) -> Result<(), WalletError> {
    let flags = parse_flags(args)?;
    let amount = parse_sango_decimal(&require_flag(&flags, "amount")?)?;
    submit_tx(
        rpc,
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
    rpc: &RpcClient,
    keyfile_path: &std::path::Path,
    args: &[String],
) -> Result<(), WalletError> {
    let flags = parse_flags(args)?;
    let validator = parse_address_arg(&require_flag(&flags, "validator")?)?;
    let amount = parse_sango_decimal(&require_flag(&flags, "amount")?)?;
    submit_tx(
        rpc,
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
    rpc: &RpcClient,
    keyfile_path: &std::path::Path,
    args: &[String],
) -> Result<(), WalletError> {
    let flags = parse_flags(args)?;
    let validator = parse_address_arg(&require_flag(&flags, "validator")?)?;
    let amount = parse_sango_decimal(&require_flag(&flags, "amount")?)?;
    submit_tx(
        rpc,
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
    rpc: &RpcClient,
    keyfile_path: &std::path::Path,
    args: &[String],
) -> Result<(), WalletError> {
    let flags = parse_flags(args)?;
    let validator = parse_address_arg(&require_flag(&flags, "validator")?)?;
    submit_tx(
        rpc,
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
    rpc: &RpcClient,
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
        rpc,
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
    rpc: &RpcClient,
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
        rpc,
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
    rpc: &RpcClient,
    keyfile_path: &std::path::Path,
    args: &[String],
) -> Result<(), WalletError> {
    let _flags = parse_flags(args)?;
    submit_tx(
        rpc,
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
    if !keyfile_path.exists() {
        // Nouveau keyfile v1 en clair (l'utilisateur pourra le chiffrer après).
        let mut kf = KeyFile::create(keyfile_path)?;
        kf.attach_evm_key(keyfile_path, None)?;
        let addr = kf.evm_address()?;
        println!("✓ Keyfile créé + clé EVM attachée");
        println!("  Adresse EVM : 0x{}", addr.to_hex());
        return Ok(());
    }

    // Keyfile existant : détecter la version.
    // On regarde la version JSON sans charger (pour éviter de demander la
    // passphrase inutilement).
    let raw: serde_json::Value = {
        let bytes = std::fs::read(keyfile_path)?;
        serde_json::from_slice(&bytes)?
    };
    let version = raw.get("version").and_then(|v| v.as_u64()).unwrap_or(0);

    match version {
        1 => {
            let mut kf = KeyFile::load(keyfile_path)?;
            if kf.has_evm_key() {
                return Err(WalletError::InvalidKeyfile(
                    "EVM key already present in keyfile".into(),
                ));
            }
            kf.attach_evm_key(keyfile_path, None)?;
            let addr = kf.evm_address()?;
            println!("✓ Clé EVM attachée au keyfile v1");
            println!("  Adresse EVM : 0x{}", addr.to_hex());
        }
        2 => {
            let pass = read_passphrase("Passphrase (keyfile v2) : ")?;
            let mut kf = KeyFile::load_encrypted(keyfile_path, &pass)?;
            if kf.has_evm_key() {
                return Err(WalletError::InvalidKeyfile(
                    "EVM key already present in keyfile".into(),
                ));
            }
            kf.attach_evm_key(keyfile_path, Some(&pass))?;
            let addr = kf.evm_address()?;
            println!("✓ Clé EVM attachée au keyfile v2");
            println!("  Adresse EVM : 0x{}", addr.to_hex());
        }
        v => {
            return Err(WalletError::InvalidKeyfile(format!(
                "unsupported keyfile version: {v}"
            )))
        }
    }
    Ok(())
}

fn cmd_evm_address(keyfile_path: &std::path::Path) -> Result<(), WalletError> {
    let kf = KeyFile::load(keyfile_path)?;
    let addr = kf.evm_address()?;
    println!("0x{}", addr.to_hex());
    Ok(())
}

fn cmd_evm_balance(
    rpc: &RpcClient,
    keyfile_path: &std::path::Path,
    args: &[String],
) -> Result<(), WalletError> {
    let addr = resolve_evm_address(keyfile_path, args)?;
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
    rpc: &RpcClient,
    keyfile_path: &std::path::Path,
    args: &[String],
) -> Result<(), WalletError> {
    let addr = resolve_evm_address(keyfile_path, args)?;
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

fn cmd_evm_call(rpc: &RpcClient, args: &[String]) -> Result<(), WalletError> {
    let flags = parse_flags(args)?;
    let to = require_flag(&flags, "to")?;
    let data = optional_flag(&flags, "data").unwrap_or("0x");
    let value = optional_flag(&flags, "value").unwrap_or("0x0");
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
    rpc: &RpcClient,
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

// --- Gestion keyfile -------------------------------------------------------

/// Lit la passphrase depuis `SANGO_WALLET_PASSPHRASE`, sinon prompt.
fn read_passphrase(prompt: &str) -> Result<Vec<u8>, WalletError> {
    if let Ok(p) = std::env::var("SANGO_WALLET_PASSPHRASE") {
        if p.is_empty() {
            return Err(WalletError::EmptyPassphrase);
        }
        return Ok(p.into_bytes());
    }
    let pass = rpassword::prompt_password(prompt)
        .map_err(|e| WalletError::Io(std::io::Error::other(e.to_string())))?;
    if pass.is_empty() {
        return Err(WalletError::EmptyPassphrase);
    }
    Ok(pass.into_bytes())
}

fn cmd_keyfile_encrypt(keyfile_path: &std::path::Path) -> Result<(), WalletError> {
    // Vérifier que le fichier est bien v1 en clair avant tout.
    let kf = KeyFile::load(keyfile_path)?;
    if kf.version != 1 {
        return Err(WalletError::AlreadyEncrypted);
    }

    println!("⚠️  Cette opération va chiffrer votre keyfile avec une passphrase.");
    println!("    La passphrase NE PEUT PAS être récupérée en cas d'oubli.");
    println!();

    let p1 = read_passphrase("Passphrase : ")?;
    let p2 = read_passphrase("Confirmer  : ")?;
    if p1 != p2 {
        return Err(WalletError::Usage("passphrases do not match".into()));
    }

    let kf2 = KeyFile::encrypt_in_place(keyfile_path, &p1)?;
    println!("✓ Keyfile chiffré (v2)");
    println!("  Adresse : 0x{}", kf2.address_hex);
    Ok(())
}

fn cmd_keyfile_decrypt(keyfile_path: &std::path::Path) -> Result<(), WalletError> {
    println!("⚠️  ATTENTION : cette opération va écrire votre seed EN CLAIR.");
    println!("    Utilisez-la uniquement pour migrer vers un autre format.");
    println!();

    let pass = read_passphrase("Passphrase : ")?;
    let kf1 = KeyFile::decrypt_in_place(keyfile_path, &pass)?;
    println!("✓ Keyfile déchiffré (v1, ⚠️ en clair)");
    println!("  Adresse : 0x{}", kf1.address_hex);
    Ok(())
}

fn cmd_keyfile_info(keyfile_path: &std::path::Path) -> Result<(), WalletError> {
    use std::fs;
    let bytes = fs::read(keyfile_path)?;
    let raw: serde_json::Value = serde_json::from_slice(&bytes)?;
    let version = raw.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
    let address_hex = raw
        .get("address_hex")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let created_at = raw.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0);

    println!("Keyfile : {}", keyfile_path.display());
    println!("  version    : {version}");
    println!("  address    : 0x{address_hex}");
    println!("  created_at : {created_at}");
    match version {
        1 => {
            println!("  chiffré    : ❌ NON (v1 en clair)");
            println!("  → migration recommandée : `sango-wallet keyfile-encrypt`");
        }
        2 => {
            let kdf = raw.get("kdf").and_then(|v| v.as_str()).unwrap_or("?");
            let cipher = raw.get("cipher").and_then(|v| v.as_str()).unwrap_or("?");
            println!("  chiffré    : ✅ OUI (v2)");
            println!("  kdf        : {kdf}");
            println!("  cipher     : {cipher}");
            if let Some(params) = raw.get("kdf_params") {
                let m = params
                    .get("m_cost_kib")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let t = params.get("t_cost").and_then(|v| v.as_u64()).unwrap_or(0);
                let p = params.get("p_cost").and_then(|v| v.as_u64()).unwrap_or(0);
                println!("  argon2     : m={m} KiB, t={t}, p={p}");
            }
        }
        _ => println!("  chiffré    : (version inconnue)"),
    }
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
    rpc: &RpcClient,
    keyfile_path: &std::path::Path,
    mut params: TxParams,
) -> Result<(), WalletError> {
    let kf = KeyFile::load(keyfile_path)?;

    params.chain_id = fetch_chain_id(rpc)?;
    let addr = kf.address()?;
    let (nonce, _, onchain_pk) = fetch_account(rpc, &addr)?;
    params.nonce = nonce;

    let declare_pk = if onchain_pk.is_none() {
        Some(kf.public_key()?)
    } else {
        None
    };

    let tx = params.build_and_sign(&kf, declare_pk)?;
    let tx_hash = send_transaction(rpc, &tx)?;
    println!("✓ Transaction envoyée");
    println!("  Hash : {tx_hash}");
    Ok(())
}
