//! `sango-faucet` — faucet HTTP minimal pour Sango V1.
//!
//! ## Usage
//!
//! ```text
//! sango-faucet --config /path/to/faucet.json
//! ```
//!
//! ## Endpoints
//!
//! - `POST /faucet` : `{ "address": "0x..." }` → `{ "tx_hash": "0x...", ... }`
//! - `GET  /health` : `{ "status": "ok", "balance": "...", ... }`
//! - `GET  /`       : mini-doc JSON (endpoints + montant + cooldown)
//!
//! ## Rate limiting
//!
//! - Par adresse : 1 drip / `cooldown_secs`.
//! - Par IP : `max_requests_per_ip` / `cooldown_secs` (sliding window).

use std::io::BufReader;
use std::net::{IpAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::thread;

use sango_primitives::NativeAddress;
use sango_rpc::http::{read_request, write_json_status, HttpRequest};

mod config;
mod faucet;

use config::Config;
use faucet::{Faucet, FaucetError};

const DEFAULT_MAX_BODY: usize = 4 * 1024;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let config_path = parse_config_path(args)?;
    let config = Config::load(&config_path).map_err(|e| format!("config: {e}"))?;

    println!("✓ Faucet configuré");
    println!("  RPC          : {}", config.rpc_url);
    println!("  Listen       : {}", config.listen_addr);
    println!("  Amount       : {} base units", config.amount_base_units);
    println!("  Cooldown/addr: {}s", config.cooldown_secs);
    println!(
        "  Max/IP       : {} / {}s",
        config.max_requests_per_ip, config.cooldown_secs
    );

    let faucet = Arc::new(Faucet::new(config));
    println!("  Faucet addr  : 0x{}", faucet.faucet_address().to_hex());
    println!();

    let listener =
        TcpListener::bind(faucet.config_listen_addr()).map_err(|e| format!("bind: {e}"))?;

    println!("✓ Faucet listening on {}", faucet.config_listen_addr());
    println!(
        "  Exemple : curl -X POST http://{}/faucet -d '{{\"address\":\"0x...\"}}'",
        faucet.config_listen_addr()
    );
    println!("  Ctrl+C pour arrêter.");
    println!();

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let faucet = Arc::clone(&faucet);
                let peer = s.peer_addr().ok().map(|a| a.ip());
                thread::spawn(move || {
                    let _ = handle_connection(s, faucet, peer);
                });
            }
            Err(e) => eprintln!("accept: {e}"),
        }
    }
    Ok(())
}

fn handle_connection(
    stream: TcpStream,
    faucet: Arc<Faucet>,
    peer: Option<IpAddr>,
) -> std::io::Result<()> {
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .ok();
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(10)))
        .ok();

    let mut reader = BufReader::new(stream);
    let mut served = 0usize;
    const MAX_REQUESTS: usize = 32;

    loop {
        if served >= MAX_REQUESTS {
            return Ok(());
        }
        let req = match read_request(&mut reader) {
            Ok(None) => return Ok(()),
            Ok(Some(r)) => r,
            Err(_) => return Ok(()),
        };
        served += 1;
        let keep_alive = req.keep_alive && served < MAX_REQUESTS;

        // Dispatch.
        let (status, reason, body) = dispatch(&faucet, &req, peer);

        // Body trop gros ?
        if req.body.len() > DEFAULT_MAX_BODY {
            let body = serde_json::json!({"error": "payload too large"}).to_string();
            let _ = write_json_status(
                reader.get_mut(),
                413,
                "Payload Too Large",
                body.as_bytes(),
                false,
            );
            return Ok(());
        }

        if write_json_status(
            reader.get_mut(),
            status,
            reason,
            body.as_bytes(),
            keep_alive,
        )
        .is_err()
        {
            return Ok(());
        }
        if !keep_alive {
            return Ok(());
        }
    }
}

fn dispatch(
    faucet: &Faucet,
    req: &HttpRequest,
    peer: Option<IpAddr>,
) -> (u16, &'static str, String) {
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") => (
            200,
            "OK",
            serde_json::json!({
                "service": "sango-faucet",
                "version": 1,
                "endpoints": {
                    "POST /faucet": { "body": { "address": "0x..." }, "returns": "tx_hash" },
                    "GET /health": "returns status + faucet balance",
                },
                "amount_base_units": faucet.amount_base_units().to_string(),
                "cooldown_secs": faucet.cooldown_secs(),
            })
            .to_string(),
        ),
        ("GET", "/health") => {
            let balance = faucet.balance_base_units().unwrap_or(0);
            (
                200,
                "OK",
                serde_json::json!({
                    "status": "ok",
                    "faucet_address": format!("0x{}", faucet.faucet_address().to_hex()),
                    "balance_base_units": balance.to_string(),
                })
                .to_string(),
            )
        }
        ("POST", "/faucet") => handle_faucet_request(faucet, req, peer),
        ("GET", "/faucet") => (
            405,
            "Method Not Allowed",
            serde_json::json!({"error": "use POST /faucet"}).to_string(),
        ),
        _ => (
            404,
            "Not Found",
            serde_json::json!({"error": "not found", "path": req.path}).to_string(),
        ),
    }
}

fn handle_faucet_request(
    faucet: &Faucet,
    req: &HttpRequest,
    peer: Option<IpAddr>,
) -> (u16, &'static str, String) {
    // Parser le body JSON.
    let parsed: serde_json::Value = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(e) => {
            return (
                400,
                "Bad Request",
                serde_json::json!({"error": format!("invalid json: {e}")}).to_string(),
            );
        }
    };

    let addr_hex = match parsed.get("address").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            return (
                400,
                "Bad Request",
                serde_json::json!({"error": "missing field `address`"}).to_string(),
            );
        }
    };

    let to = match NativeAddress::from_hex(addr_hex) {
        Ok(a) => a,
        Err(e) => {
            return (
                400,
                "Bad Request",
                serde_json::json!({"error": format!("invalid address: {e}")}).to_string(),
            );
        }
    };

    match faucet.request(to, peer) {
        Ok(tx_hash) => (
            200,
            "OK",
            serde_json::json!({
                "tx_hash": tx_hash,
                "amount_base_units": faucet.amount_base_units().to_string(),
                "to": format!("0x{}", to.to_hex()),
            })
            .to_string(),
        ),
        Err(FaucetError::RateLimited { remaining_secs }) => (
            429,
            "Too Many Requests",
            serde_json::json!({
                "error": "rate limited",
                "reason": "address cooldown",
                "remaining_secs": remaining_secs,
            })
            .to_string(),
        ),
        Err(FaucetError::RateLimitedPerIp) => (
            429,
            "Too Many Requests",
            serde_json::json!({
                "error": "rate limited",
                "reason": "ip limit",
            })
            .to_string(),
        ),
        Err(FaucetError::Wallet(e)) => (
            502,
            "Bad Gateway",
            serde_json::json!({"error": format!("rpc: {e}")}).to_string(),
        ),
    }
}

// --- CLI --------------------------------------------------------------------

fn parse_config_path(args: &[String]) -> Result<PathBuf, String> {
    // Seul le premier argument est inspecté : `--config <PATH>` ou
    // `--help`. Les autres formes sont rejetées explicitement. Un
    // `while` serait signalé par clippy `never_loop` (tous les bras
    // retournent ou exitent), d'où la forme linéaire.
    let first = args
        .first()
        .ok_or_else(|| "missing --config <PATH>".to_string())?;
    match first.as_str() {
        "--config" => {
            let v = args.get(1).ok_or("--config needs a value")?;
            Ok(PathBuf::from(v))
        }
        "--help" | "-h" => {
            print_help();
            std::process::exit(0);
        }
        other => Err(format!("unknown arg: {other}")),
    }
}

fn print_help() {
    println!(
        "sango-faucet — faucet HTTP pour Sango V1\n\
         \n\
         USAGE:\n\
         \x20   sango-faucet --config <PATH>\n\
         \n\
         Le fichier de config est un JSON avec les champs :\n\
         \x20   rpc_url              (requis)\n\
         \x20   listen_addr          (requis, ex. \"0.0.0.0:3000\")\n\
         \x20   faucet_seed_hex      (requis, 32 bytes hex)\n\
         \x20   amount_sango         (défaut \"100\")\n\
         \x20   cooldown_secs        (défaut 3600)\n\
         \x20   max_requests_per_ip  (défaut 5)\n\
         \x20   max_fee_base_units   (défaut 1000)\n"
    );
}
