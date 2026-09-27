//! Helpers de rendu HTML : escape, formatage, layout, CSS.

use std::time::{SystemTime, UNIX_EPOCH};

/// Échappe les caractères HTML dangereux.
///
/// L'explorer n'affiche que des valeurs validées comme hex (adresses,
/// hashs), mais on applique l'escape partout par défense en profondeur.
#[must_use]
pub fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Tronque un hex en gardant un début et une fin, avec `…`.
///
/// `shorten("0x1234567890abcdef", 6, 4)` → `"0x1234…cdef"`
#[must_use]
pub fn shorten(s: &str, head: usize, tail: usize) -> String {
    if s.len() <= head + tail + 1 {
        return s.to_string();
    }
    let h: String = s.chars().take(head).collect();
    let t: String = s.chars().skip(s.len() - tail).collect();
    format!("{h}…{t}")
}

/// Formate un timestamp Unix en « il y a Xs/min/h/j ».
#[must_use]
pub fn relative_time(ts: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if ts >= now {
        return "à l'instant".into();
    }
    let delta = now - ts;
    if delta < 60 {
        format!("il y a {delta}s")
    } else if delta < 3600 {
        format!("il y a {}min", delta / 60)
    } else if delta < 86_400 {
        format!("il y a {}h", delta / 3600)
    } else {
        format!("il y a {}j", delta / 86_400)
    }
}

/// Affiche un montant en base units, formaté.
#[must_use]
pub fn format_amount(u: u128) -> String {
    let sango = u / 10_000_000;
    let frac = u % 10_000_000;
    if frac == 0 {
        format!("{sango}")
    } else {
        let mut s = format!("{frac:07}");
        while s.ends_with('0') {
            s.pop();
        }
        format!("{sango}.{s}")
    }
}

/// CSS inline.
pub const CSS: &str = r#"
:root {
  --bg: #0d1117; --fg: #c9d1d9; --muted: #8b949e;
  --accent: #58a6ff; --border: #30363d; --card: #161b22;
  --green: #3fb950; --red: #f85149; --yellow: #d29922;
}
* { box-sizing: border-box; }
body {
  margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background: var(--bg); color: var(--fg); font-size: 14px; line-height: 1.5;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
header {
  padding: 1rem 2rem; border-bottom: 1px solid var(--border);
  display: flex; align-items: center; justify-content: space-between;
}
header h1 { margin: 0; font-size: 1.15rem; font-weight: 600; }
header h1 a { color: var(--fg); }
header .network { color: var(--muted); font-size: 0.85rem; margin-left: 0.75rem; }
header nav a { margin-left: 1.25rem; }
main { max-width: 1200px; margin: 0 auto; padding: 1.5rem 2rem; }
.card {
  background: var(--card); border: 1px solid var(--border);
  border-radius: 6px; padding: 1rem 1.25rem; margin-bottom: 1.25rem;
}
.card h2 { margin: 0 0 0.75rem 0; font-size: 1rem; font-weight: 600; }
.card h2 .muted { font-weight: 400; font-size: 0.85rem; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 0.5rem 0.75rem; text-align: left; vertical-align: top; }
th {
  color: var(--muted); font-weight: 500; font-size: 0.8rem;
  text-transform: uppercase; letter-spacing: 0.05em;
  border-bottom: 1px solid var(--border);
}
tbody tr { border-bottom: 1px solid var(--border); }
tbody tr:last-child { border-bottom: none; }
tbody tr:hover { background: rgba(88,166,255,0.04); }
.mono { font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 0.9em; }
.muted { color: var(--muted); }
.green { color: var(--green); }
.red { color: var(--red); }
.yellow { color: var(--yellow); }
.tag {
  display: inline-block; padding: 1px 6px; border-radius: 3px;
  background: var(--border); font-size: 0.75rem;
  font-family: ui-monospace, Menlo, monospace;
}
.tag.native { background: rgba(63,185,80,0.15); color: var(--green); }
.tag.evm { background: rgba(88,166,255,0.15); color: var(--accent); }
.kv { display: grid; grid-template-columns: 200px 1fr; gap: 0.4rem 1rem; }
.kv dt { color: var(--muted); }
.kv dd { margin: 0; word-break: break-all; }
.pagination { display: flex; gap: 1rem; align-items: center; margin-top: 1rem; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 1.25rem; }
.stat { background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: 1rem 1.25rem; }
.stat .label { color: var(--muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }
.stat .value { font-size: 1.5rem; font-weight: 600; margin-top: 0.25rem; }
.empty { color: var(--muted); padding: 1.5rem 0; text-align: center; }
.error-page { max-width: 600px; margin: 4rem auto; text-align: center; }
.error-page h1 { font-size: 3rem; margin: 0; color: var(--muted); }
.error-page p { color: var(--muted); }
footer { text-align: center; padding: 1.5rem; color: var(--muted); font-size: 0.8rem; }
"#;

/// Layout HTML commun.
#[must_use]
pub fn layout(title: &str, network: &str, body: &str) -> String {
    let title_e = escape(title);
    let network_e = escape(network);
    format!(
        r#"<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title_e} — Sango Explorer</title>
<style>{CSS}</style>
</head>
<body>
<header>
  <h1><a href="/">Sango Explorer</a><span class="network">{network_e}</span></h1>
  <nav>
    <a href="/">Accueil</a>
    <a href="/blocks">Blocs</a>
    <a href="/validators">Validateurs</a>
    <a href="/health">Health</a>
  </nav>
</header>
<main>
{body}
</main>
<footer>Sango V1 — explorer minimaliste</footer>
</body>
</html>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_all_special_chars() {
        assert_eq!(escape("<script>&\"'"), "&lt;script&gt;&amp;&quot;&#39;");
    }

    #[test]
    fn shorten_keeps_head_and_tail() {
        assert_eq!(shorten("0x1234567890abcdef", 6, 4), "0x1234…cdef");
        assert_eq!(shorten("short", 6, 4), "short");
    }

    #[test]
    fn format_amount_integer() {
        assert_eq!(format_amount(0), "0");
        assert_eq!(format_amount(10_000_000), "1");
        assert_eq!(format_amount(1_000_000_000), "100");
    }

    #[test]
    fn format_amount_fractional() {
        assert_eq!(format_amount(15_000_000), "1.5");
        assert_eq!(format_amount(12_345_678), "1.2345678");
    }

    #[test]
    fn relative_time_formats() {
        // Le résultat dépend de `now`, mais on peut au moins vérifier
        // qu'un timestamp futur proche retourne la version « instant ».
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(relative_time(now), "à l'instant");
        assert!(relative_time(now - 5).contains("5s"));
        assert!(relative_time(now - 120).contains("2min"));
    }
}
