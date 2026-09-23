//! Binaire `sango-node` : assemble le nœud, le driver consensus, le RPC
//! et le service P2P optionnel.
//!
//! ## Usage
//!
//! ```text
//! sango-node --config devnet.json [--data-dir DIR] [--rpc-addr ADDR]
//!            [--p2p-listen ADDR]... [--p2p-bootstrap ADDR]... [--mdns]
//! ```
//!
//! ## Architecture
//!
//! - **Thread principal** : boucle consensus (propose un bloc à intervalle
//!   fixe si nous sommes proposer).
//! - **Runtime tokio** : service P2P dans une tâche async dédiée.
//! - **Thread secondaire** : serveur RPC.
//! - **Persistance** : RocksDB dans `--data-dir`, flushée à chaque bloc.
//!
//! ## Modes
//!
//! - **Autonome** (sans `--p2p-listen`) : self-loopback local. Utile pour
//!   les démos mono-validateur.
//! - **Réseau** (avec `--p2p-listen`) : publie et écoute sur le réseau.
//!   `--p2p-bootstrap` permet de se connecter à des pairs au démarrage.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use sango_p2p::{Multiaddr, PeerId};

use sango_consensus::{LocalIdentity, Validator, ValidatorSet};
use sango_node::{Driver, Node, NodeBackend, NodeHandle, OutgoingMessage, RuntimeGenesis};
use sango_p2p::{P2pConfig, P2pEvent};
use sango_primitives::Epoch;
use sango_rpc::RpcServer;

const DEFAULT_DATA_DIR: &str = "./sango-data";
const DEFAULT_RPC_ADDR: &str = "127.0.0.1:8545";
const BLOCK_INTERVAL_MS: u64 = 500;
const P2P_DRAIN_PER_TICK: usize = 100;

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

    // Extraire tous les champs dont on a besoin **avant** de déplacer quoi
    // que ce soit, pour éviter les partial moves ultérieurs.
    let config_path = opts
        .config
        .clone()
        .ok_or_else(|| "--config <PATH> is required".to_string())?;
    let data_dir = opts
        .data_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DATA_DIR));
    let rpc_addr: SocketAddr = opts
        .rpc_addr
        .clone()
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
    let _rpc_shutdown = server.shutdown_handle();
    let _rpc_thread = thread::spawn(move || {
        if let Err(e) = server.serve() {
            eprintln!("rpc server error: {e}");
        }
    });

    // --- 8. Runtime tokio + service P2P -----------------------------------
    let p2p_enabled = !opts.no_p2p && (!opts.p2p_listen.is_empty() || opts.mdns);

    let mut _p2p_runtime: Option<tokio::runtime::Runtime> = None;
    let p2p_service: Option<sango_p2p::P2pService> = if p2p_enabled {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .build()
            .map_err(|e| format!("tokio runtime: {e}"))?;
        let _guard = rt.enter();

        let cfg = build_p2p_config(&opts)?;
        let p2p_handle = sango_p2p::spawn(cfg).map_err(|e| format!("p2p spawn: {e}"))?;
        let svc = p2p_handle.service.clone();

        // Attendre un premier NewListenAddr pour l'afficher.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(P2pEvent::NewListenAddr(addr)) = svc.try_recv_event() {
                println!("✓ P2P listening on {addr}");
                break;
            }
            if std::time::Instant::now() > deadline {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }

        // Garder le runtime vivant.
        _p2p_runtime = Some(rt);
        Some(svc)
    } else {
        None
    };

    // --- 9. Driver consensus ----------------------------------------------
    let mut driver = Driver::new(handle.clone(), validator_set, local, Epoch::new(0))
        .map_err(|e| format!("driver new: {e}"))?;

    if let Some(svc) = p2p_service.clone() {
        driver.attach_p2p(svc);
    }

    // --- 10. Message de démarrage -----------------------------------------
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
    if p2p_service.is_some() {
        println!("║  P2P        : ENABLED                                    ║");
    } else {
        println!("║  P2P        : disabled (self-loopback)                   ║");
    }
    if genesis.rewards_enabled {
        println!("║  Rewards    : ENABLED                                    ║");
    } else {
        println!("║  Rewards    : disabled                                   ║");
    }
    println!("║  Ctrl+C pour arrêter.                                    ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    // --- 11. Boucle principale --------------------------------------------
    let tick = Duration::from_millis(BLOCK_INTERVAL_MS);
    loop {
        // 11a. Drainer les événements P2P entrants.
        if driver.has_p2p() {
            let _ = driver.drain_p2p_events(P2P_DRAIN_PER_TICK);
        }

        // 11b. Tenter de proposer.
        driver
            .maybe_propose()
            .map_err(|e| format!("maybe_propose: {e}"))?;

        // 11c. Self-loopback : pour un nœud seul, on traite ses propres
        //      messages. En présence de P2P, cela reste utile pour éviter
        //      d'attendre l'écho réseau.
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

        // 11d. Événements (commits, changements de round).
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
    // `p2p_runtime` doit rester vivant jusqu'à la fin du processus : on
    // l'utilise dans un bloc unreachable pour satisfaire le compilateur.
    #[allow(unreachable_code)]
    {
        drop(_p2p_runtime);
        _rpc_shutdown.shutdown();
        let _ = _rpc_thread.join();
        Ok(())
    }
}

// --- Parse P2P config -------------------------------------------------------

fn build_p2p_config(opts: &CliOpts) -> Result<P2pConfig, String> {
    // Listen addresses.
    let listen_addrs: Vec<Multiaddr> = if opts.p2p_listen.is_empty() {
        // Aucune adresse → binding par défaut.
        vec!["/ip4/127.0.0.1/udp/0/quic-v1"
            .parse()
            .map_err(|e| format!("default listen addr: {e}"))?]
    } else {
        opts.p2p_listen
            .iter()
            .map(|s| {
                s.parse::<Multiaddr>()
                    .map_err(|e| format!("bad --p2p-listen {s}: {e}"))
            })
            .collect::<Result<_, _>>()?
    };

    // Bootstrap addresses : forme `/ip4/.../udp/.../quic-v1/p2p/<PeerId>`.
    let bootstrap_addrs: Vec<(Multiaddr, PeerId)> = opts
        .p2p_bootstrap
        .iter()
        .map(|s| parse_bootstrap(s))
        .collect::<Result<_, _>>()?;

    Ok(P2pConfig {
        listen_addrs,
        bootstrap_addrs,
        mdns_enabled: opts.mdns,
        ..Default::default()
    })
}

/// Parse `/ip4/.../udp/.../quic-v1/p2p/<PeerId>` en `(addr, peer_id)`.
fn parse_bootstrap(s: &str) -> Result<(Multiaddr, PeerId), String> {
    let mut addr: Multiaddr = s
        .parse()
        .map_err(|e| format!("bad --p2p-bootstrap {s}: {e}"))?;

    // Extraire le dernier composant (peer id).
    let peer_id = match addr.pop() {
        Some(sango_p2p::multiaddr::Protocol::P2p(peer_id)) => peer_id,
        _ => {
            return Err(format!("--p2p-bootstrap {s} must end with /p2p/<PeerId>"));
        }
    };
    Ok((addr, peer_id))
}

// --- CLI --------------------------------------------------------------------

#[derive(Debug, Default)]
struct CliOpts {
    config: Option<PathBuf>,
    data_dir: Option<PathBuf>,
    rpc_addr: Option<String>,
    p2p_listen: Vec<String>,
    p2p_bootstrap: Vec<String>,
    mdns: bool,
    no_p2p: bool,
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
            "--p2p-listen" => {
                let v = args.get(i + 1).ok_or("--p2p-listen needs a value")?;
                opts.p2p_listen.push(v.clone());
                i += 2;
            }
            "--p2p-bootstrap" => {
                let v = args.get(i + 1).ok_or("--p2p-bootstrap needs a value")?;
                opts.p2p_bootstrap.push(v.clone());
                i += 2;
            }
            "--mdns" => {
                opts.mdns = true;
                i += 1;
            }
            "--no-p2p" => {
                opts.no_p2p = true;
                i += 1;
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
         \x20   sango-node --config <PATH> [OPTIONS]\n\
         \n\
         REQUIRED:\n\
         \x20   --config <PATH>            Fichier genesis JSON\n\
         \n\
         OPTIONS:\n\
         \x20   --data-dir <PATH>          Répertoire RocksDB (défaut : {DEFAULT_DATA_DIR})\n\
         \x20   --rpc-addr <ADDR>          Adresse d'écoute RPC (défaut : {DEFAULT_RPC_ADDR})\n\
         \n\
         P2P (désactivé par défaut) :\n\
         \x20   --p2p-listen <MULTIADDR>   Adresse d'écoute (répétable)\n\
         \x20                              Ex : /ip4/0.0.0.0/udp/9000/quic-v1\n\
         \x20   --p2p-bootstrap <MULTIADDR> Adresse bootstrap (répétable)\n\
         \x20                              Format : /ip4/.../udp/.../quic-v1/p2p/<PeerId>\n\
         \x20   --mdns                     Active la découverte locale mDNS\n\
         \x20   --no-p2p                   Force P2P désactivé\n\
         \n\
         \x20   --help, -h                 Affiche cette aide\n"
    );
}
