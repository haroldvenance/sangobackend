//! Binaire `sango-node` : assemble le nœud, le driver consensus et le RPC.
//!
//! ## Usage
//!
//! ```text
//! sango-node --config devnet.json [--data-dir ./data] [--rpc-addr 127.0.0.1:8545]
//! ```
//!
//! ## Architecture
//!
//! - **Thread principal** : boucle consensus (propose un bloc toutes les
//!   500 ms si nous sommes proposer).
//! - **Thread secondaire** : serveur RPC sur `--rpc-addr`.
//! - **Persistance** : RocksDB dans `--data-dir`, flushée à chaque bloc.
//!
//! ## Réseau P2P
//!
//! **Non implémenté en V1.** Le binaire boucle les messages sortants du
//! driver sur lui-même (self-loopback). Cela signifie qu'il ne fonctionne
//! que pour un réseau **à un seul validateur** — c'est suffisant pour les
//! démonstrations locales et les tests du wallet.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use sango_consensus::{LocalIdentity, Validator, ValidatorSet};
use sango_node::{Driver, Node, NodeBackend, NodeHandle, OutgoingMessage, RuntimeGenesis};
use sango_primitives::Epoch;
use sango_rpc::RpcServer;

const DEFAULT_DATA_DIR: &str = "./sango-data";
const DEFAULT_RPC_ADDR: &str = "127.0.0.1:8545";
const BLOCK_INTERVAL_MS: u64 = 500;

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
    let opts = parse_args(args)?;

    let config_path = opts
        .config
        .ok_or_else(|| "--config <PATH> is required".to_string())?;
    let data_dir = opts
        .data_dir
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DATA_DIR));
    let rpc_addr: SocketAddr = opts
        .rpc_addr
        .unwrap_or_else(|| DEFAULT_RPC_ADDR.to_string())
        .parse()
        .map_err(|e| format!("invalid --rpc-addr: {e}"))?;

    // --- 1. Charger la config ---------------------------------------------
    let genesis = RuntimeGenesis::load(&config_path).map_err(|e| format!("config load: {e}"))?;

    // --- 2. Ouvrir ou créer le nœud ---------------------------------------
    let mut node = if genesis.rewards_enabled {
        Node::open_with_rewards(&data_dir, genesis.chain_id, genesis.initial_supply)
    } else {
        Node::open(&data_dir, genesis.chain_id, genesis.initial_supply)
    }
    .map_err(|e| format!("node open: {e}"))?;

    // --- 3. Genesis state (si nœud vierge) --------------------------------
    let already_init = node.tip().is_some();
    if !already_init {
        node.initialize_genesis(&genesis.accounts, &genesis.validators)
            .map_err(|e| format!("initialize_genesis: {e}"))?;
        println!(
            "✓ Genesis appliqué : {} comptes, {} validateurs",
            genesis.accounts.len(),
            genesis.validators.len()
        );
    } else {
        println!("✓ État restauré depuis {}", data_dir.display());
    }

    // --- 4. NodeHandle partagé -------------------------------------------
    let handle = NodeHandle::new(node);

    // --- 5. Validator set -------------------------------------------------
    let vs_validators: Vec<Validator> = genesis
        .validators
        .iter()
        .map(|v| Validator {
            address: v.address,
            public_key: v.public_key,
            voting_power: v.voting_power().base_units(),
        })
        .collect();
    let validator_set =
        ValidatorSet::new(vs_validators).map_err(|e| format!("validator set: {e}"))?;

    // --- 6. Identité locale -----------------------------------------------
    let local = genesis.local_keypair.map(LocalIdentity::new);

    // --- 7. RPC server (thread secondaire) --------------------------------
    let backend = Arc::new(NodeBackend::new(handle.clone()));
    let server =
        RpcServer::bind(rpc_addr, backend).map_err(|e| format!("rpc bind {rpc_addr}: {e}"))?;
    // On garde `_rpc_shutdown` et `_rpc_thread` vivants pour la durée du
    // processus : le serveur RPC tourne dans un thread détaché qui se
    // termine quand le processus est tué.
    let _rpc_shutdown = server.shutdown_handle();
    let _rpc_thread = thread::spawn(move || {
        if let Err(e) = server.serve() {
            eprintln!("rpc server error: {e}");
        }
    });

    // --- 8. Driver consensus ----------------------------------------------
    let mut driver = Driver::new(handle.clone(), validator_set, local, Epoch::new(0))
        .map_err(|e| format!("driver new: {e}"))?;

    // --- 9. Message de démarrage ------------------------------------------
    println!();
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║                SANGO NODE — V1                           ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  Chain ID   : 0x{}…  ║", &genesis.chain_id.to_hex()[..16]);
    println!("║  Data dir   : {:<43} ║", data_dir.display().to_string());
    println!("║  RPC        : {:<43} ║", rpc_addr);
    match driver.local_address() {
        Some(addr) => {
            let s = format!("0x{}…", &addr.to_hex()[..16]);
            println!("║  Validator  : {:<43} ║", s);
        }
        None => println!("║  Validator  : (non-validator)                            ║"),
    }
    if genesis.rewards_enabled {
        println!("║  Rewards    : ENABLED                                    ║");
    } else {
        println!("║  Rewards    : disabled                                   ║");
    }
    println!("║  Ctrl+C pour arrêter.                                    ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    // --- 10. Boucle principale --------------------------------------------
    let tick = Duration::from_millis(BLOCK_INTERVAL_MS);
    loop {
        // 10a. Tenter de proposer.
        driver
            .maybe_propose()
            .map_err(|e| format!("maybe_propose: {e}"))?;

        // 10b. Self-loopback : redonner les messages sortants au driver.
        //      (remplace P2P en single-validator)
        let outgoing = driver.drain_outbox();
        for msg in outgoing {
            match msg {
                OutgoingMessage::Proposal(p) => {
                    let _ = driver.handle_proposal(*p);
                }
                OutgoingMessage::Prevote(v) => {
                    let _ = driver.handle_prevote(v);
                }
                OutgoingMessage::Precommit(c) => {
                    let _ = driver.handle_precommit(c);
                }
            }
        }

        // 10c. Événements (commits, changements de round).
        for event in driver.drain_events() {
            match event {
                sango_node::DriverEvent::Committed {
                    height, block_hash, ..
                } => {
                    println!(
                        "✓ Bloc #{} commit 0x{}…",
                        height.get(),
                        &block_hash.to_hex()[..16]
                    );
                }
                sango_node::DriverEvent::RoundAdvanced(r) => {
                    println!("  → round avancé à {}", r.get());
                }
            }
        }

        thread::sleep(tick);
    }

    // Note : la boucle ci-dessus ne se termine jamais normalement. Sur
    // Ctrl+C, le processus est terminé par le signal par défaut. Les
    // écritures RocksDB sont flushées après chaque bloc, donc aucune
    // perte de données.
    //
    // On garde les variables pour éviter les avertissements.
    #[allow(unreachable_code)]
    {
        _rpc_shutdown.shutdown();
        let _ = _rpc_thread.join();
        Ok(())
    }
}

#[derive(Debug, Default)]
struct CliOpts {
    config: Option<PathBuf>,
    data_dir: Option<PathBuf>,
    rpc_addr: Option<String>,
}

fn parse_args(args: &[String]) -> Result<CliOpts, String> {
    let mut opts = CliOpts::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                let v = args.get(i + 1).ok_or("--config needs a value")?;
                opts.config = Some(PathBuf::from(v));
                i += 2;
            }
            "--data-dir" => {
                let v = args.get(i + 1).ok_or("--data-dir needs a value")?;
                opts.data_dir = Some(PathBuf::from(v));
                i += 2;
            }
            "--rpc-addr" => {
                let v = args.get(i + 1).ok_or("--rpc-addr needs a value")?;
                opts.rpc_addr = Some(v.clone());
                i += 2;
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other => return Err(format!("unknown arg: {other}")),
        }
    }
    Ok(opts)
}

fn print_help() {
    println!(
        "sango-node — nœud Sango V1\n\
         \n\
         USAGE:\n\
         \x20   sango-node --config <PATH> [--data-dir <PATH>] [--rpc-addr <ADDR>]\n\
         \n\
         OPTIONS:\n\
         \x20   --config <PATH>     Fichier genesis JSON (obligatoire)\n\
         \x20   --data-dir <PATH>   Répertoire RocksDB (défaut : {DEFAULT_DATA_DIR})\n\
         \x20   --rpc-addr <ADDR>   Adresse d'écoute RPC (défaut : {DEFAULT_RPC_ADDR})\n\
         \x20   --help, -h          Affiche cette aide\n"
    );
}
