//! `sango-explorer` — explorer HTTP minimaliste pour Sango V1.
//!
//! ## Usage
//!
//! ```text
//! sango-explorer --config /path/to/explorer.json
//! ```
//!
//! ## Routes
//!
//! - `GET /` — dashboard (chain info + derniers blocs)
//! - `GET /blocks?page=N` — liste paginée des blocs
//! - `GET /block/:height` — détail d'un bloc
//! - `GET /tx/:hash` — détail d'une transaction
//! - `GET /address/:addr[?page=N]` — détail d'une adresse
//! - `GET /validators` — liste des validateurs
//! - `GET /health` — statut JSON
//!
//! ## Choix techniques
//!
//! - **Serveur HTTP** : réutilise [`sango_rpc::http`] (comme le faucet).
//!   Pas d'Axum, pas de tokio — la stack reste minimale.
//! - **Client RPC** : réutilise [`sango_wallet::RpcClient`]. Aucun client
//!   dupliqué.
//! - **Décodage** : les blocs et txs sont décodés côté explorer via
//!   `sango-types` + `sango-codec`. Aucune modif backend.

use std::io::{BufReader, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use sango_rpc::http::{read_request, write_preflight_ok, HttpRequest};

mod config;
mod error;
mod html;
mod pages;
mod rpc;

use config::Config;
use rpc::Rpc;

/// Nombre maximum de requêtes servies sur une même connexion.
const MAX_REQUESTS: usize = 64;

/// Timeout d'inactivité sur chaque connexion.
const IDLE_TIMEOUT_SECS: u64 = 30;

/// Explorer partagé.
struct Explorer {
    rpc: Rpc,
    network_name: String,
}

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

    println!("✓ Explorer configuré");
    println!("  RPC          : {}", config.rpc_url);
    println!("  Listen       : {}", config.listen_addr);
    println!("  Réseau       : {}", config.network_name);
    println!();

    let explorer = Arc::new(Explorer {
        rpc: Rpc::new(&config.rpc_url),
        network_name: config.network_name.clone(),
    });

    // Ping initial pour signaler si le RPC est joignable.
    match explorer.rpc.chain_info() {
        Ok(_) => println!("✓ RPC joignable"),
        Err(e) => eprintln!("⚠️  RPC non joignable : {e}"),
    }

    let listener = TcpListener::bind(config.listen_addr).map_err(|e| format!("bind: {e}"))?;
    println!("✓ Explorer listening on http://{}", config.listen_addr);
    println!("  Exemple : http://{}/", config.listen_addr);
    println!("  Ctrl+C pour arrêter.");
    println!();

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let explorer = Arc::clone(&explorer);
                let peer = s.peer_addr().ok().map(|a| a.ip());
                thread::spawn(move || {
                    let _ = handle_connection(s, explorer, peer);
                });
            }
            Err(e) => eprintln!("accept: {e}"),
        }
    }
    Ok(())
}

fn handle_connection(
    stream: TcpStream,
    explorer: Arc<Explorer>,
    _peer: Option<IpAddr>,
) -> std::io::Result<()> {
    stream
        .set_read_timeout(Some(Duration::from_secs(IDLE_TIMEOUT_SECS)))
        .ok();
    stream
        .set_write_timeout(Some(Duration::from_secs(IDLE_TIMEOUT_SECS)))
        .ok();

    let mut reader = BufReader::new(stream);
    let mut served = 0usize;

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

        // CORS preflight — explorer en lecture seule, on accepte OPTIONS
        // sur toutes les routes.
        if req.method == "OPTIONS" {
            if write_preflight_ok(reader.get_mut(), keep_alive, "GET, OPTIONS").is_err() {
                return Ok(());
            }
            if !keep_alive {
                return Ok(());
            }
            continue;
        }

        if req.method != "GET" {
            let body = pages::error_page(&explorer.network_name, "Méthode non autorisée");
            if write_html(
                reader.get_mut(),
                405,
                "Method Not Allowed",
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
            continue;
        }

        let (status, reason, body) = route(&explorer, &req);
        if write_html(
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

/// Routeur principal. Retourne `(status, reason, html_body)`.
fn route(explorer: &Explorer, req: &HttpRequest) -> (u16, &'static str, String) {
    let (path, query) = parse_query(&req.path);
    let network = &explorer.network_name;

    match path {
        "/" | "" => (200, "OK", pages::dashboard(&explorer.rpc, network)),
        "/health" => (200, "OK", pages::health(&explorer.rpc)),
        "/validators" => (200, "OK", pages::validators(&explorer.rpc, network)),
        "/blocks" => {
            let (limit, offset) = parse_pagination(&query, 20, 100);
            (
                200,
                "OK",
                pages::blocks(&explorer.rpc, network, limit, offset),
            )
        }
        "/search" => {
            let q = query
                .iter()
                .find(|(k, _)| k == "q")
                .map(|(_, v)| v.as_str())
                .unwrap_or("");
            (200, "OK", pages::search(&explorer.rpc, network, q))
        }
        _ => {
            if let Some(rest) = path.strip_prefix("/block/") {
                return match rest.parse::<u64>() {
                    Ok(h) => (200, "OK", pages::block(&explorer.rpc, network, h)),
                    Err(_) => (
                        400,
                        "Bad Request",
                        pages::error_page(network, "Hauteur de bloc invalide"),
                    ),
                };
            }
            if let Some(rest) = path.strip_prefix("/tx/") {
                return (200, "OK", pages::tx(&explorer.rpc, network, rest));
            }
            if let Some(rest) = path.strip_prefix("/address/") {
                let (limit, offset) = parse_pagination(&query, 20, 100);
                return (
                    200,
                    "OK",
                    pages::address(&explorer.rpc, network, rest, limit as u32, offset as u32),
                );
            }
            (
                404,
                "Not Found",
                pages::error_page(network, "Page introuvable"),
            )
        }
    }
}

/// Extrait path + query (`?k=v&k2=v2`) sans dépendance URL.
fn parse_query(full: &str) -> (&str, Vec<(String, String)>) {
    let mut parts = full.splitn(2, '?');
    let path = parts.next().unwrap_or("");
    let query_str = parts.next().unwrap_or("");
    let mut query = Vec::new();
    for pair in query_str.split('&') {
        if pair.is_empty() {
            continue;
        }
        if let Some((k, v)) = pair.split_once('=') {
            query.push((k.to_string(), v.to_string()));
        }
    }
    (path, query)
}

/// Parse les paramètres de pagination.
///
/// ## Format recommandé
///
/// `?limit=N&offset=M` — `limit` plafonné à `max_limit`, `offset`
/// non borné. Les deux valent leur défaut si absents ou invalides.
///
/// ## Compatibilité `?page=N`
///
/// `?page=N` reste accepté : équivaut à `offset = (N − 1) × limit`.
/// Si `page` et `offset` sont tous deux fournis, `page` est prioritaire.
fn parse_pagination(query: &[(String, String)], default_limit: u64, max_limit: u64) -> (u64, u64) {
    let mut limit = default_limit;
    let mut offset = 0u64;
    let mut page: Option<u64> = None;
    for (k, v) in query {
        match k.as_str() {
            "limit" => {
                if let Ok(n) = v.parse::<u64>() {
                    limit = n.clamp(1, max_limit);
                }
            }
            "offset" => {
                if let Ok(n) = v.parse::<u64>() {
                    offset = n;
                }
            }
            "page" => {
                if let Ok(n) = v.parse::<u64>() {
                    page = Some(n);
                }
            }
            _ => {}
        }
    }
    if let Some(p) = page {
        if p >= 1 {
            offset = (p - 1).saturating_mul(limit);
        }
    }
    (limit, offset)
}

/// Écrit une réponse HTML.
///
/// Équivalent de `sango_rpc::http::write_json_status`, mais avec
/// `Content-Type: text/html`.
fn write_html<W: Write>(
    stream: &mut W,
    status: u16,
    reason: &str,
    body: &[u8],
    keep_alive: bool,
) -> std::io::Result<()> {
    let conn = if keep_alive { "keep-alive" } else { "close" };
    let header = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: {}\r\n\
         Access-Control-Allow-Origin: *\r\n\
         \r\n",
        status,
        reason,
        body.len(),
        conn
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

// --- CLI --------------------------------------------------------------------

fn parse_config_path(args: &[String]) -> Result<PathBuf, String> {
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
        "sango-explorer — explorer HTTP pour Sango V1\n\
         \n\
         USAGE:\n\
         \x20   sango-explorer --config <PATH>\n\
         \n\
         Le fichier de config est un JSON avec les champs :\n\
         \x20   rpc_url       (requis, ex. \"http://127.0.0.1:8545\")\n\
         \x20   listen_addr   (requis, ex. \"127.0.0.1:8080\")\n\
         \x20   network_name  (défaut \"Sango\")\n"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn parse_config_requires_value() {
        assert!(parse_config_path(&s(&["--config"])).is_err());
    }

    #[test]
    fn parse_config_ok() {
        let p = parse_config_path(&s(&["--config", "/tmp/x.json"])).unwrap();
        assert_eq!(p.to_string_lossy(), "/tmp/x.json");
    }

    #[test]
    fn parse_query_no_query() {
        let (p, q) = parse_query("/blocks");
        assert_eq!(p, "/blocks");
        assert!(q.is_empty());
    }

    #[test]
    fn parse_query_with_params() {
        let (p, q) = parse_query("/address/0xabc?page=3");
        assert_eq!(p, "/address/0xabc");
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].0, "page");
        assert_eq!(q[0].1, "3");
    }

    #[test]
    fn parse_query_multiple() {
        let (_, q) = parse_query("/x?a=1&b=2");
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn pagination_defaults() {
        let (l, o) = parse_pagination(&[], 20, 100);
        assert_eq!(l, 20);
        assert_eq!(o, 0);
    }

    #[test]
    fn pagination_limit_and_offset() {
        let q = vec![
            ("limit".to_string(), "50".to_string()),
            ("offset".to_string(), "100".to_string()),
        ];
        let (l, o) = parse_pagination(&q, 20, 100);
        assert_eq!(l, 50);
        assert_eq!(o, 100);
    }

    #[test]
    fn pagination_limit_clamped() {
        let q = vec![("limit".to_string(), "1000".to_string())];
        let (l, _) = parse_pagination(&q, 20, 100);
        assert_eq!(l, 100);
    }

    #[test]
    fn pagination_page_fallback() {
        // ?page=3 avec limit 20 → offset = 40.
        let q = vec![
            ("page".to_string(), "3".to_string()),
            ("limit".to_string(), "20".to_string()),
        ];
        let (l, o) = parse_pagination(&q, 20, 100);
        assert_eq!(l, 20);
        assert_eq!(o, 40);
    }

    #[test]
    fn pagination_page_overrides_offset() {
        let q = vec![
            ("page".to_string(), "2".to_string()),
            ("offset".to_string(), "999".to_string()),
            ("limit".to_string(), "10".to_string()),
        ];
        let (_, o) = parse_pagination(&q, 20, 100);
        assert_eq!(o, 10);
    }
}
