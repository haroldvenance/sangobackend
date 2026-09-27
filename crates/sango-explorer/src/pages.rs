//! Rendu HTML de chaque page.

use sango_primitives::{Hash32, NativeAddress};
use sango_types::{Block, Transaction, Tx};

use crate::html::{escape, format_amount, layout, relative_time, shorten};
use crate::rpc::{Rpc, TxWithLoc};

/// Nombre de blocs par page dans `/blocks`.
pub const BLOCKS_PER_PAGE: u64 = 20;

/// Blocs affichés sur le dashboard.
pub const DASHBOARD_BLOCKS: u64 = 10;

/// Nombre de txs affichées par page dans `/address/:addr`.
pub const TXS_PER_PAGE: u32 = 20;

// --- Dashboard -------------------------------------------------------------

/// Page d'accueil : info chaîne + derniers blocs.
#[must_use]
pub fn dashboard(rpc: &Rpc, network: &str) -> String {
    let info = match rpc.chain_info() {
        Ok(v) => v,
        Err(e) => return error_page(network, &format!("RPC: {e}")),
    };
    let chain_id = info
        .get("chainId")
        .and_then(|x| x.as_str())
        .unwrap_or("0x?");
    let height = info.get("height").and_then(|x| x.as_u64());
    let validator_count = info
        .get("validatorCount")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);

    let mut body = String::new();
    body.push_str("<div class=\"stats\">");
    body.push_str(&format!(
        "<div class=\"stat\"><div class=\"label\">Chain ID</div><div class=\"value mono\" style=\"font-size:1rem\">{}</div></div>",
        escape(&shorten(chain_id, 10, 6))
    ));
    body.push_str(&format!(
        "<div class=\"stat\"><div class=\"label\">Hauteur</div><div class=\"value\">{}</div></div>",
        height.map(|h| h.to_string()).unwrap_or_else(|| "—".into())
    ));
    body.push_str(&format!(
        "<div class=\"stat\"><div class=\"label\">Validateurs</div><div class=\"value\">{validator_count}</div></div>",
    ));
    body.push_str("</div>");

    body.push_str("<div class=\"card\"><h2>Derniers blocs</h2>");
    match height {
        None => body.push_str("<div class=\"empty\">Aucun bloc</div>"),
        Some(tip) => {
            body.push_str(
                "<table><thead><tr>\
                 <th>Hauteur</th><th>Hash</th><th>Proposeur</th>\
                 <th>Transactions</th><th>Âge</th>\
                 </tr></thead><tbody>",
            );
            let from = tip.saturating_sub(DASHBOARD_BLOCKS - 1);
            for h in (from..=tip).rev() {
                if let Ok(Some(block)) = rpc.get_block(h) {
                    body.push_str(&block_row(&block));
                }
            }
            body.push_str("</tbody></table>");
        }
    }
    body.push_str("</div>");

    layout("Accueil", network, &body)
}

fn block_row(block: &Block) -> String {
    let h = block.header.height.get();
    let hash = block.hash();
    let n_txs = block.transactions.len();
    let txs_label = if n_txs == 0 {
        "<span class=\"muted\">0</span>".into()
    } else {
        format!("{n_txs}")
    };
    format!(
        "<tr>\
         <td><a href=\"/block/{h}\">{h}</a></td>\
         <td class=\"mono\"><a href=\"/block/{h}\">{hash_link}</a></td>\
         <td class=\"mono muted\">{proposer}</td>\
         <td>{txs_label}</td>\
         <td class=\"muted\">{age}</td>\
         </tr>",
        hash_link = escape(&shorten(&format!("0x{}", hash.to_hex()), 14, 8)),
        proposer = escape(&shorten(
            &format!("0x{}", block.header.proposer_address.to_hex()),
            10,
            6
        )),
        age = relative_time(block.header.timestamp),
    )
}

// --- Liste des blocs -------------------------------------------------------

/// Liste paginée des blocs.
#[must_use]
pub fn blocks(rpc: &Rpc, network: &str, page: u64) -> String {
    let page = page.max(1);
    let tip = match rpc.block_number() {
        Ok(Some(h)) => h,
        Ok(None) => {
            return layout(
                "Blocs",
                network,
                "<div class=\"card\"><h2>Blocs</h2><div class=\"empty\">Aucun bloc</div></div>",
            )
        }
        Err(e) => return error_page(network, &format!("RPC: {e}")),
    };

    let offset = (page - 1) * BLOCKS_PER_PAGE;
    if offset > tip {
        return layout(
            "Blocs",
            network,
            "<div class=\"card\"><div class=\"empty\">Page vide</div></div>",
        );
    }
    let to = tip.saturating_sub(offset);
    let from = to.saturating_sub(BLOCKS_PER_PAGE - 1);

    let mut body = String::from("<div class=\"card\"><h2>Blocs <span class=\"muted\">page ");
    body.push_str(&page.to_string());
    body.push_str("</span></h2>");
    body.push_str(
        "<table><thead><tr>\
         <th>Hauteur</th><th>Hash</th><th>Proposeur</th>\
         <th>Transactions</th><th>Âge</th>\
         </tr></thead><tbody>",
    );
    for h in (from..=to).rev() {
        if let Ok(Some(block)) = rpc.get_block(h) {
            body.push_str(&block_row(&block));
        }
    }
    body.push_str("</tbody></table>");

    body.push_str("<div class=\"pagination\">");
    if page > 1 {
        body.push_str(&format!(
            "<a href=\"/blocks?page={}\">← Précédent</a>",
            page - 1
        ));
    }
    body.push_str(&format!("<span class=\"muted\">Page {page}</span>"));
    let next_offset = offset + BLOCKS_PER_PAGE;
    if next_offset <= tip {
        body.push_str(&format!(
            "<a href=\"/blocks?page={}\">Suivant →</a>",
            page + 1
        ));
    }
    body.push_str("</div>");

    body.push_str("</div>");
    layout("Blocs", network, &body)
}

// --- Détail bloc -----------------------------------------------------------

/// Détail d'un bloc.
#[must_use]
pub fn block(rpc: &Rpc, network: &str, height: u64) -> String {
    let block = match rpc.get_block(height) {
        Ok(Some(b)) => b,
        Ok(None) => return error_page(network, &format!("Bloc #{height} introuvable")),
        Err(e) => return error_page(network, &format!("RPC: {e}")),
    };

    let mut body = String::new();
    let h = block.header.height.get();
    let hash = block.hash();

    body.push_str("<div class=\"card\"><h2>Bloc #");
    body.push_str(&h.to_string());
    body.push_str("</h2><dl class=\"kv\">");
    body.push_str(&kv(
        "Hash",
        &format!("<span class=\"mono\">0x{}</span>", hash.to_hex()),
    ));
    body.push_str(&kv(
        "Parent",
        &if block.header.previous_block_hash == Hash32::ZERO {
            "<span class=\"muted\">genesis</span>".into()
        } else {
            let ph = format!("0x{}", block.header.previous_block_hash.to_hex());
            match rpc.get_block(h.saturating_sub(1)) {
                Ok(Some(p)) => {
                    let link = format!("/block/{}", p.header.height.get());
                    format!(
                        "<a class=\"mono\" href=\"{link}\">{}</a>",
                        escape(&shorten(&ph, 14, 8))
                    )
                }
                _ => format!("<span class=\"mono\">{}</span>", escape(&ph)),
            }
        },
    ));
    body.push_str(&kv(
        "Timestamp",
        &format!(
            "{} <span class=\"muted\">({})</span>",
            block.header.timestamp,
            relative_time(block.header.timestamp)
        ),
    ));
    body.push_str(&kv(
        "Proposeur",
        &addr_link(&format!("0x{}", block.header.proposer_address.to_hex())),
    ));
    body.push_str(&kv(
        "Gas used / limit",
        &format!("{} / {}", block.header.gas_used, block.header.gas_limit),
    ));
    body.push_str(&kv("Base fee", &block.header.base_fee.to_string()));
    body.push_str(&kv(
        "Transaction root",
        &format!(
            "<span class=\"mono\">{}</span>",
            escape(&shorten(
                &format!("0x{}", block.header.transaction_root.to_hex()),
                14,
                8
            ))
        ),
    ));
    body.push_str(&kv(
        "State root",
        &format!(
            "<span class=\"mono\">{}</span>",
            escape(&shorten(
                &format!("0x{}", block.header.state_root.to_hex()),
                14,
                8
            ))
        ),
    ));
    body.push_str(&kv(
        "Receipt root",
        &format!(
            "<span class=\"mono\">{}</span>",
            escape(&shorten(
                &format!("0x{}", block.header.receipt_root.to_hex()),
                14,
                8
            ))
        ),
    ));
    body.push_str("</dl></div>");

    body.push_str("<div class=\"card\"><h2>Transactions <span class=\"muted\">");
    body.push_str(&block.transactions.len().to_string());
    body.push_str("</span></h2>");
    if block.transactions.is_empty() {
        body.push_str("<div class=\"empty\">Aucune transaction</div>");
    } else {
        body.push_str(
            "<table><thead><tr>\
             <th>#</th><th>Hash</th><th>Type</th><th>De</th>\
             <th>Vers</th><th>Valeur</th>\
             </tr></thead><tbody>",
        );
        for (i, tx) in block.transactions.iter().enumerate() {
            body.push_str(&tx_row(rpc, tx, i as u32));
        }
        body.push_str("</tbody></table>");
    }
    body.push_str("</div>");

    // Vue Ethereum (eth_getBlockByNumber) — debug : permet de comparer
    // les deux représentations du même bloc.
    if let Ok(Some(eth_block)) = rpc.eth_get_block_by_number(h, false) {
        body.push_str(&eth_view_section(&eth_block));
    }

    layout(&format!("Bloc #{h}"), network, &body)
}

/// Rendu HTML de la vue Ethereum d'un bloc (`eth_getBlockByNumber`).
///
/// Dump compact des champs Ethereum-only : `logsBloom`, `receiptsRoot`
/// (format hex Ethereum), `sha3Uncles`, `size`, `baseFeePerGas`.
fn eth_view_section(eth_block: &serde_json::Value) -> String {
    let field = |k: &str| -> String {
        eth_block
            .get(k)
            .and_then(|x| x.as_str())
            .map(|s| {
                if s.len() > 30 {
                    format!("<span class=\"mono\">{}</span>", escape(&shorten(s, 14, 8)))
                } else {
                    format!("<span class=\"mono\">{}</span>", escape(s))
                }
            })
            .unwrap_or_else(|| "<span class=\"muted\">—</span>".into())
    };

    let mut out = String::from(
        "<div class=\"card\"><h2>Vue Ethereum <span class=\"muted\">(eth_getBlockByNumber)</span></h2><dl class=\"kv\">",
    );
    out.push_str(&kv("Number", &field("number")));
    out.push_str(&kv("Hash", &field("hash")));
    out.push_str(&kv("Parent hash", &field("parentHash")));
    out.push_str(&kv("State root", &field("stateRoot")));
    out.push_str(&kv("Transactions root", &field("transactionsRoot")));
    out.push_str(&kv("Receipts root", &field("receiptsRoot")));
    out.push_str(&kv("Logs bloom", &field("logsBloom")));
    out.push_str(&kv("Gas used", &field("gasUsed")));
    out.push_str(&kv("Gas limit", &field("gasLimit")));
    out.push_str(&kv("Base fee", &field("baseFeePerGas")));
    out.push_str(&kv("Size", &field("size")));
    out.push_str(&kv("Timestamp", &field("timestamp")));
    out.push_str(&kv(
        "Miner",
        "<span class=\"muted\">adresse nulle (proposeur Sango natif)</span>",
    ));
    out.push_str("</dl></div>");
    out
}

fn tx_row(rpc: &Rpc, tx: &Tx, index: u32) -> String {
    let hash = tx.hash();
    let (kind_class, kind_label, from, to, value) = match tx {
        Tx::Native(t) => (
            "native",
            "natif",
            format!("0x{}", t.sender.to_hex()),
            t.recipient
                .map(|r| format!("0x{}", r.to_hex()))
                .unwrap_or_else(|| "—".into()),
            format_amount(t.value.base_units()),
        ),
        Tx::Evm(t) => {
            let from = rpc
                .eth_get_transaction(&hash)
                .ok()
                .flatten()
                .and_then(|v| v.get("from").and_then(|x| x.as_str()).map(str::to_string))
                .unwrap_or_else(|| "(récupéré)".into());
            (
                "evm",
                "evm",
                from,
                t.to()
                    .map(|r| format!("0x{}", r.to_hex()))
                    .unwrap_or_else(|| "(création)".into()),
                format!("{:#x}", t.value()),
            )
        }
    };
    format!(
        "<tr>\
         <td class=\"muted\">{index}</td>\
         <td class=\"mono\"><a href=\"/tx/0x{hash_hex}\">{hash_short}</a></td>\
         <td><span class=\"tag {kind_class}\">{kind_label}</span></td>\
         <td class=\"mono\">{from}</td>\
         <td class=\"mono\">{to}</td>\
         <td class=\"mono\">{value}</td>\
         </tr>",
        hash_hex = hash.to_hex(),
        hash_short = escape(&shorten(&format!("0x{}", hash.to_hex()), 14, 8)),
        from = escape(&shorten(&from, 12, 8)),
        to = escape(&shorten(&to, 12, 8)),
    )
}

// --- Détail transaction ----------------------------------------------------

/// Détail d'une transaction.
#[must_use]
pub fn tx(rpc: &Rpc, network: &str, hash_hex: &str) -> String {
    let hash = match Hash32::from_hex(hash_hex) {
        Ok(h) => h,
        Err(e) => return error_page(network, &format!("Hash invalide : {e}")),
    };
    let tx = match rpc.get_transaction(&hash) {
        Ok(Some(t)) => t,
        Ok(None) => return error_page(network, "Transaction introuvable"),
        Err(e) => return error_page(network, &format!("RPC: {e}")),
    };

    let mut body = String::new();
    body.push_str("<div class=\"card\"><h2>Transaction</h2><dl class=\"kv\">");
    body.push_str(&kv(
        "Hash",
        &format!("<span class=\"mono\">0x{}</span>", tx.tx.hash().to_hex()),
    ));
    body.push_str(&kv(
        "Bloc",
        &format!(
            "<a href=\"/block/{}\">#{}</a> (index {})",
            tx.block_height, tx.block_height, tx.tx_index
        ),
    ));
    if let Some(bh) = tx.block_hash {
        body.push_str(&kv(
            "Block hash",
            &format!("<span class=\"mono\">0x{}</span>", bh.to_hex()),
        ));
    }

    match &tx.tx {
        Tx::Native(t) => native_tx_fields(&mut body, t),
        Tx::Evm(t) => evm_tx_fields(&mut body, t),
    }
    body.push_str("</dl></div>");

    // Section receipt.
    let tx_hash = tx.tx.hash();
    match &tx.tx {
        Tx::Evm(_) => match rpc.eth_get_receipt(&tx_hash) {
            Ok(Some(receipt)) => body.push_str(&receipt_section(&receipt)),
            Ok(None) => body.push_str(
                "<div class=\"card\"><h2>Receipt</h2><div class=\"empty\">Receipt non disponible (tx non incluse ou pas encore indexée)</div></div>",
            ),
            Err(e) => body.push_str(&format!(
                "<div class=\"card\"><h2>Receipt</h2><div class=\"empty\">Erreur : {}</div></div>",
                escape(&e.to_string())
            )),
        },
        Tx::Native(_) => body.push_str(
            "<div class=\"card\"><h2>Receipt</h2><div class=\"empty\">Pas de receipt exposé pour les transactions natives en V1</div></div>",
        ),
    }

    layout("Transaction", network, &body)
}

/// Rendu HTML de la section receipt EVM.
fn receipt_section(receipt: &serde_json::Value) -> String {
    let status = receipt
        .get("status")
        .and_then(|x| x.as_str())
        .unwrap_or("0x?");
    let status_label = if status == "0x1" {
        "<span class=\"green\">Succès</span>"
    } else {
        "<span class=\"red\">Échec</span>"
    };
    let gas_used = receipt
        .get("gasUsed")
        .and_then(|x| x.as_str())
        .unwrap_or("0x0");
    let cum_gas = receipt
        .get("cumulativeGasUsed")
        .and_then(|x| x.as_str())
        .unwrap_or("0x0");
    let contract = receipt.get("contractAddress").and_then(|x| x.as_str());

    let mut out = String::from("<div class=\"card\"><h2>Receipt</h2><dl class=\"kv\">");
    out.push_str(&kv("Statut", status_label));
    out.push_str(&kv("Gas utilisé", &escape(gas_used)));
    out.push_str(&kv("Gas cumulé (bloc)", &escape(cum_gas)));
    if let Some(c) = contract {
        out.push_str(&kv("Contrat créé", &addr_link(c)));
    }
    out.push_str("</dl>");

    if let Some(logs) = receipt.get("logs").and_then(|x| x.as_array()) {
        out.push_str(&format!(
            "<h2 style=\"margin-top:1rem\">Logs <span class=\"muted\">{}</span></h2>",
            logs.len()
        ));
        if logs.is_empty() {
            out.push_str("<div class=\"empty\">Aucun log</div>");
        } else {
            out.push_str(
                "<table><thead><tr>\
                 <th>Index</th><th>Adresse</th><th>Topics</th><th>Data</th>\
                 </tr></thead><tbody>",
            );
            for log in logs {
                let idx = log.get("logIndex").and_then(|x| x.as_str()).unwrap_or("?");
                let addr = log.get("address").and_then(|x| x.as_str()).unwrap_or("");
                let data = log.get("data").and_then(|x| x.as_str()).unwrap_or("0x");
                let topics_str = log
                    .get("topics")
                    .and_then(|x| x.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|t| t.as_str())
                            .map(|t| {
                                format!("<div class=\"mono\">{}</div>", escape(&shorten(t, 14, 8)))
                            })
                            .collect::<Vec<_>>()
                            .join("")
                    })
                    .unwrap_or_default();
                out.push_str(&format!(
                    "<tr>\
                     <td class=\"mono\">{}</td>\
                     <td class=\"mono\">{}</td>\
                     <td>{}</td>\
                     <td class=\"mono\">{}</td>\
                     </tr>",
                    escape(idx),
                    addr_link(addr),
                    topics_str,
                    escape(&shorten(data, 20, 10)),
                ));
            }
            out.push_str("</tbody></table>");
        }
    }
    out.push_str("</div>");
    out
}

// --- Recherche -------------------------------------------------------------

/// Page `/search?q=X`.
///
/// Heuristique :
/// - `123` → `/block/123`
/// - `0x` + 64 hex → tx hash (via `sango_getTransactionByHash`)
/// - `0x` + 40 hex → adresse
/// - autre → page d'erreur
#[must_use]
pub fn search(rpc: &Rpc, network: &str, query: &str) -> String {
    let q = query.trim();
    if q.is_empty() {
        return error_page(network, "Recherche vide");
    }

    // Nombre pur → bloc.
    if q.chars().all(|c| c.is_ascii_digit()) {
        if let Ok(h) = q.parse::<u64>() {
            return block(rpc, network, h);
        }
    }

    // 0x + hex.
    if let Some(hex) = q.strip_prefix("0x").or_else(|| q.strip_prefix("0X")) {
        match hex.len() {
            64 => {
                if let Ok(h) = Hash32::from_hex(q) {
                    // 1. Tx ?
                    if let Ok(Some(_)) = rpc.get_transaction(&h) {
                        return tx(rpc, network, &format!("0x{}", h.to_hex()));
                    }
                    // 2. Bloc ? On utilise eth_getBlockByHash (retourne
                    // le numéro de bloc, qu'on peut router vers /block/N).
                    if let Ok(Some(blk)) = rpc.eth_get_block_by_hash(&h, false) {
                        if let Some(num_hex) = blk.get("number").and_then(|x| x.as_str()) {
                            if let Ok(num) =
                                u64::from_str_radix(num_hex.trim_start_matches("0x"), 16)
                            {
                                return block(rpc, network, num);
                            }
                        }
                    }
                }
                return error_page(
                    network,
                    &format!("Hash introuvable (ni tx ni bloc) : {}", escape(q)),
                );
            }
            40 => {
                return address(rpc, network, q, 1);
            }
            _ => {
                return error_page(
                    network,
                    &format!(
                        "Longueur de hash invalide : {} (attendu 40 ou 64)",
                        hex.len()
                    ),
                );
            }
        }
    }

    error_page(
        network,
        "Format non reconnu. Utilise : nombre (bloc), 0x…40 (adresse), 0x…64 (tx)",
    )
}

fn native_tx_fields(body: &mut String, t: &Transaction) {
    body.push_str(&kv(
        "Type",
        &format!("<span class=\"tag native\">natif — {:?}</span>", t.tx_kind),
    ));
    body.push_str(&kv(
        "Sender",
        &addr_link(&format!("0x{}", t.sender.to_hex())),
    ));
    if let Some(r) = t.recipient {
        body.push_str(&kv(
            "Destinataire",
            &addr_link(&format!("0x{}", r.to_hex())),
        ));
    }
    body.push_str(&kv("Nonce", &t.nonce.to_string()));
    body.push_str(&kv(
        "Valeur",
        &format!("{} SANGO", format_amount(t.value.base_units())),
    ));
    body.push_str(&kv("Gas limit", &t.gas_limit.to_string()));
    body.push_str(&kv("Max fee", &format!("{} base units/gas", t.max_fee)));
    body.push_str(&kv(
        "Priority fee",
        &format!("{} base units/gas", t.priority_fee),
    ));
    if !t.data.is_empty() {
        body.push_str(&kv(
            "Data",
            &format!("<span class=\"mono\">0x{}</span>", hex::encode(&t.data)),
        ));
    }
    if let Some(pk) = t.public_key {
        body.push_str(&kv(
            "Public key",
            &format!("<span class=\"mono\">0x{}</span>", pk.to_hex()),
        ));
    }
}

fn evm_tx_fields(body: &mut String, t: &sango_types::EvmTx) {
    body.push_str(&kv(
        "Type",
        &format!(
            "<span class=\"tag evm\">evm — 0x{:x}</span>",
            t.kind().tag()
        ),
    ));
    if let Some(to) = t.to() {
        body.push_str(&kv(
            "Destinataire",
            &addr_link(&format!("0x{}", to.to_hex())),
        ));
    } else {
        body.push_str(&kv(
            "Destinataire",
            "<span class=\"muted\">(création de contrat)</span>",
        ));
    }
    body.push_str(&kv("Nonce", &t.nonce().to_string()));
    body.push_str(&kv("Valeur", &format!("{:#x}", t.value())));
    body.push_str(&kv("Gas limit", &t.gas_limit().to_string()));
    if !t.data().is_empty() {
        body.push_str(&kv(
            "Input",
            &format!("<span class=\"mono\">0x{}</span>", hex::encode(t.data())),
        ));
    }
}

// --- Adresse ---------------------------------------------------------------

/// Détail d'une adresse.
#[must_use]
pub fn address(rpc: &Rpc, network: &str, addr_hex: &str, page: u32) -> String {
    let addr = match NativeAddress::from_hex(addr_hex) {
        Ok(a) => a,
        Err(e) => return error_page(network, &format!("Adresse invalide : {e}")),
    };

    let mut body = String::new();
    body.push_str("<div class=\"card\"><h2>Adresse</h2><dl class=\"kv\">");
    body.push_str(&kv(
        "Native",
        &format!("<span class=\"mono\">0x{}</span>", addr.to_hex()),
    ));

    match rpc.get_account(&addr) {
        Ok(Some(acc)) => {
            body.push_str(&kv(
                "Solde",
                &format!(
                    "{} SANGO <span class=\"muted\">({} base units)</span>",
                    format_amount(acc.balance),
                    acc.balance
                ),
            ));
            body.push_str(&kv("Nonce", &acc.nonce.to_string()));
            if let Some(pk) = acc.public_key {
                body.push_str(&kv(
                    "Public key",
                    &format!(
                        "<span class=\"mono\">{}</span>",
                        escape(&shorten(&pk, 14, 8))
                    ),
                ));
            } else {
                body.push_str(&kv(
                    "Public key",
                    "<span class=\"muted\">non enregistrée</span>",
                ));
            }
        }
        Ok(None) => {
            body.push_str(&kv(
                "Solde",
                "<span class=\"muted\">compte inexistant</span>",
            ));
        }
        Err(e) => {
            body.push_str(&kv("Erreur RPC", &escape(&e.to_string())));
        }
    }
    body.push_str("</dl></div>");

    if let Ok(Some(v)) = rpc.get_validator_info(&addr) {
        body.push_str("<div class=\"card\"><h2>Validateur</h2><dl class=\"kv\">");
        body.push_str(&kv("Self stake", &json_amount(&v, "selfStake")));
        body.push_str(&kv("Total délégué", &json_amount(&v, "totalDelegated")));
        body.push_str(&kv("Voting power", &json_amount(&v, "votingPower")));
        let comm = v.get("commissionBps").and_then(|x| x.as_u64()).unwrap_or(0);
        body.push_str(&kv(
            "Commission",
            &format!("{} bps ({:.2} %)", comm, comm as f64 / 100.0),
        ));
        let jailed = v.get("jailed").and_then(|x| x.as_bool()).unwrap_or(false);
        body.push_str(&kv(
            "Jailed",
            if jailed {
                "<span class=\"red\">oui</span>"
            } else {
                "<span class=\"green\">non</span>"
            },
        ));
        body.push_str("</dl></div>");
    }

    if let Ok(delegations) = rpc.get_delegations(&addr) {
        if !delegations.is_empty() {
            body.push_str("<div class=\"card\"><h2>Délégations <span class=\"muted\">");
            body.push_str(&delegations.len().to_string());
            body.push_str(
                "</span></h2><table><thead><tr>\
                 <th>Validateur</th><th>Bonded</th><th>Unbonding</th><th>Récompenses</th>\
                 </tr></thead><tbody>",
            );
            for d in &delegations {
                let val = d.get("validator").and_then(|x| x.as_str()).unwrap_or("");
                body.push_str(&format!(
                    "<tr>\
                     <td class=\"mono\">{}</td>\
                     <td>{}</td>\
                     <td>{}</td>\
                     <td>{}</td>\
                     </tr>",
                    addr_link(val),
                    json_amount(d, "bonded"),
                    json_amount(d, "unbonding"),
                    json_amount(d, "pendingRewards"),
                ));
            }
            body.push_str("</tbody></table></div>");
        }
    }

    if let Ok(pending) = rpc.get_pending_unbondings(&addr) {
        if !pending.is_empty() {
            body.push_str("<div class=\"card\"><h2>Unbondings en attente <span class=\"muted\">");
            body.push_str(&pending.len().to_string());
            body.push_str(
                "</span></h2><table><thead><tr>\
                 <th>ID</th><th>Validateur</th><th>Montant</th><th>Mature à</th>\
                 </tr></thead><tbody>",
            );
            for p in &pending {
                let id = p.get("id").and_then(|x| x.as_u64()).unwrap_or(0);
                let val = p.get("validator").and_then(|x| x.as_str()).unwrap_or("");
                let mature_at = p.get("matureAt").and_then(|x| x.as_u64()).unwrap_or(0);
                body.push_str(&format!(
                    "<tr>\
                     <td class=\"mono\">{id}</td>\
                     <td class=\"mono\">{}</td>\
                     <td>{}</td>\
                     <td>{} <span class=\"muted\">({})</span></td>\
                     </tr>",
                    addr_link(val),
                    json_amount(p, "amount"),
                    mature_at,
                    relative_time(mature_at),
                ));
            }
            body.push_str("</tbody></table></div>");
        }
    }

    let offset = page.saturating_sub(1) * TXS_PER_PAGE;
    match rpc.txs_by_address(&addr, TXS_PER_PAGE, offset) {
        Ok((txs, total)) => {
            body.push_str("<div class=\"card\"><h2>Transactions émises <span class=\"muted\">");
            body.push_str(&format!("{total} au total"));
            body.push_str("</span></h2>");
            if txs.is_empty() {
                body.push_str(
                    "<div class=\"empty\">Aucune transaction émise par cette adresse</div>",
                );
            } else {
                body.push_str(
                    "<table><thead><tr>\
                     <th>Hash</th><th>Bloc</th><th>Type</th><th>Vers</th><th>Valeur</th>\
                     </tr></thead><tbody>",
                );
                for t in &txs {
                    body.push_str(&tx_with_loc_row(t));
                }
                body.push_str("</tbody></table>");

                let total_pages = (total as u32).div_ceil(TXS_PER_PAGE);
                if total_pages > 1 {
                    body.push_str("<div class=\"pagination\">");
                    if page > 1 {
                        body.push_str(&format!(
                            "<a href=\"/address/{addr_hex}?page={}\">← Précédent</a>",
                            page - 1
                        ));
                    }
                    body.push_str(&format!(
                        "<span class=\"muted\">Page {page} / {total_pages}</span>"
                    ));
                    if page < total_pages {
                        body.push_str(&format!(
                            "<a href=\"/address/{addr_hex}?page={}\">Suivant →</a>",
                            page + 1
                        ));
                    }
                    body.push_str("</div>");
                }
            }
            body.push_str("</div>");
        }
        Err(e) => {
            body.push_str(&format!(
                "<div class=\"card\"><div class=\"empty\">Historique indisponible : {}</div></div>",
                escape(&e.to_string())
            ));
        }
    }

    layout(&format!("Adresse 0x{}", addr.to_hex()), network, &body)
}

fn tx_with_loc_row(t: &TxWithLoc) -> String {
    let hash = t.tx.hash();
    let (kind_class, kind_label, to, value) = match &t.tx {
        Tx::Native(nt) => (
            "native",
            "natif",
            nt.recipient
                .map(|r| format!("0x{}", r.to_hex()))
                .unwrap_or_else(|| "—".into()),
            format_amount(nt.value.base_units()),
        ),
        Tx::Evm(et) => (
            "evm",
            "evm",
            et.to()
                .map(|r| format!("0x{}", r.to_hex()))
                .unwrap_or_else(|| "(création)".into()),
            format!("{:#x}", et.value()),
        ),
    };
    format!(
        "<tr>\
         <td class=\"mono\"><a href=\"/tx/0x{}\">{}</a></td>\
         <td><a href=\"/block/{}\">#{}</a></td>\
         <td><span class=\"tag {kind_class}\">{kind_label}</span></td>\
         <td class=\"mono\">{}</td>\
         <td class=\"mono\">{value}</td>\
         </tr>",
        hash.to_hex(),
        escape(&shorten(&format!("0x{}", hash.to_hex()), 14, 8)),
        t.block_height,
        t.block_height,
        escape(&shorten(&to, 12, 8)),
    )
}

// --- Validateurs -----------------------------------------------------------

/// Liste des validateurs.
#[must_use]
pub fn validators(rpc: &Rpc, network: &str) -> String {
    let validators = match rpc.get_validators() {
        Ok(v) => v,
        Err(e) => return error_page(network, &format!("RPC: {e}")),
    };

    let mut body = String::new();
    body.push_str("<div class=\"card\"><h2>Validateurs <span class=\"muted\">");
    body.push_str(&validators.len().to_string());
    body.push_str("</span></h2>");

    if validators.is_empty() {
        body.push_str("<div class=\"empty\">Aucun validateur</div>");
    } else {
        body.push_str(
            "<table><thead><tr>\
             <th>Adresse</th><th>Self stake</th><th>Délégué</th>\
             <th>Voting power</th><th>Commission</th><th>Jailed</th>\
             </tr></thead><tbody>",
        );
        for v in &validators {
            let addr = v.get("address").and_then(|x| x.as_str()).unwrap_or("");
            let comm = v.get("commissionBps").and_then(|x| x.as_u64()).unwrap_or(0);
            let jailed = v.get("jailed").and_then(|x| x.as_bool()).unwrap_or(false);
            body.push_str(&format!(
                "<tr>\
                 <td class=\"mono\">{}</td>\
                 <td>{}</td>\
                 <td>{}</td>\
                 <td>{}</td>\
                 <td>{comm} bps</td>\
                 <td>{}</td>\
                 </tr>",
                addr_link(addr),
                json_amount(v, "selfStake"),
                json_amount(v, "totalDelegated"),
                json_amount(v, "votingPower"),
                if jailed {
                    "<span class=\"red\">oui</span>"
                } else {
                    "<span class=\"green\">non</span>"
                },
            ));
        }
        body.push_str("</tbody></table>");
    }
    body.push_str("</div>");

    layout("Validateurs", network, &body)
}

// --- Health ----------------------------------------------------------------

/// Page `/health` : JSON chaîne.
#[must_use]
pub fn health(rpc: &Rpc) -> String {
    use crate::html::CSS;
    match rpc.chain_info() {
        Ok(info) => {
            let body = format!(
                "<div class=\"card\"><h2>Statut</h2><pre class=\"mono\">{}</pre></div>",
                escape(&serde_json::to_string_pretty(&info).unwrap_or_default())
            );
            format!(
                r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>health</title><style>{CSS}</style></head><body><main>{body}</main></body></html>"#
            )
        }
        Err(e) => error_page("Sango", &format!("RPC indisponible : {e}")),
    }
}

// --- Helpers ---------------------------------------------------------------

fn kv(key: &str, val: &str) -> String {
    format!("<dt>{}</dt><dd>{}</dd>", escape(key), val)
}

fn addr_link(hex: &str) -> String {
    if hex.is_empty() {
        return "<span class=\"muted\">—</span>".into();
    }
    format!(
        "<a href=\"/address/{}\">{}</a>",
        escape(hex),
        escape(&shorten(hex, 14, 8)),
    )
}

fn json_amount(v: &serde_json::Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(|s| format!("{} SANGO", format_amount(s.parse().unwrap_or(0))))
        .unwrap_or_else(|| "—".into())
}

/// Page d'erreur.
#[must_use]
pub fn error_page(network: &str, msg: &str) -> String {
    let body = format!(
        "<div class=\"error-page\">\
         <h1>Erreur</h1>\
         <p>{}</p>\
         <p><a href=\"/\">← Retour à l'accueil</a></p>\
         </div>",
        escape(msg)
    );
    layout("Erreur", network, &body)
}
