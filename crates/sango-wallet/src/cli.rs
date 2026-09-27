//! Parser d'arguments minimal.

use crate::error::WalletError;

/// Options globales extraites avant le dispatch.
#[derive(Debug, Default)]
pub struct GlobalOpts {
    /// Endpoint RPC. Défaut : `127.0.0.1:8545`.
    pub rpc: Option<String>,
    /// Chemin du keyfile. Défaut : `~/.sango/wallet.json`.
    pub keyfile: Option<String>,
    /// Chemin vers une CA TLS custom (PEM ou DER). Active HTTPS.
    pub rpc_tls_ca: Option<String>,
    /// Accepte tout certificat TLS (devnet uniquement). Active HTTPS.
    pub rpc_tls_insecure: bool,
}

/// Parse `argv` (sans le nom du binaire) en `(GlobalOpts, commande, args)`.
pub fn parse_args(args: &[String]) -> Result<(GlobalOpts, String, Vec<String>), WalletError> {
    let mut opts = GlobalOpts::default();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--rpc" {
            let v = args
                .get(i + 1)
                .ok_or_else(|| WalletError::Usage("--rpc needs a value".into()))?;
            opts.rpc = Some(v.clone());
            i += 2;
        } else if a == "--keyfile" {
            let v = args
                .get(i + 1)
                .ok_or_else(|| WalletError::Usage("--keyfile needs a value".into()))?;
            opts.keyfile = Some(v.clone());
            i += 2;
        } else if a == "--rpc-tls-ca" {
            let v = args
                .get(i + 1)
                .ok_or_else(|| WalletError::Usage("--rpc-tls-ca needs a value".into()))?;
            opts.rpc_tls_ca = Some(v.clone());
            i += 2;
        } else if a == "--rpc-tls-insecure" {
            opts.rpc_tls_insecure = true;
            i += 1;
        } else if a == "--help" || a == "-h" {
            return Err(WalletError::Usage(HELP.to_string()));
        } else if a.starts_with("--") {
            return Err(WalletError::Usage(format!("unknown option: {a}")));
        } else {
            // Commande + args restants.
            let cmd = a.clone();
            let rest = args[i + 1..].to_vec();
            return Ok((opts, cmd, rest));
        }
    }
    Err(WalletError::Usage("missing command".into()))
}

/// Parse les paires `--flag value` après la commande.
pub fn parse_flags(args: &[String]) -> Result<Vec<(String, String)>, WalletError> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(name) = a.strip_prefix("--") {
            let value = args
                .get(i + 1)
                .ok_or_else(|| WalletError::Usage(format!("--{name} needs a value")))?;
            out.push((name.to_string(), value.clone()));
            i += 2;
        } else {
            return Err(WalletError::Usage(format!("unexpected argument: {a}")));
        }
    }
    Ok(out)
}

/// Retourne la valeur d'un flag ou une erreur.
pub fn require_flag(flags: &[(String, String)], name: &str) -> Result<String, WalletError> {
    flags
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.clone())
        .ok_or_else(|| WalletError::Usage(format!("missing flag --{name}")))
}

/// Retourne la valeur optionnelle d'un flag.
pub fn optional_flag<'a>(flags: &'a [(String, String)], name: &str) -> Option<&'a str> {
    flags
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// Texte d'aide.
pub const HELP: &str = "\
sango-wallet — wallet CLI pour Sango V1

USAGE:
    sango-wallet [--rpc URL] [--keyfile PATH] <commande> [--flags...]

COMMANDES NATIVES:
    new                                 Génère un nouveau keyfile
    address                             Affiche l'adresse native
    pubkey                              Affiche la clé publique Ed25519
    balance [ADDR]                      Solde natif
    nonce [ADDR]                        Nonce natif
    info                                Informations chaîne
    history [ADDR] [--limit N] [--offset M]
                                        Transactions natives d'une adresse
                                        (défaut : limit=20, offset=0)
    send --to ADDR --amount SANGO       Transfert natif
    stake|unstake --amount SANGO
    delegate|undelegate --validator ADDR --amount SANGO
    claim --validator ADDR
    register-validator --commission-bps N --amount SANGO
    update-commission --new-bps N
    unjail

COMMANDES EVM:
    evm-new                             Attache une clé secp256k1
    evm-address                         Adresse EVM locale
    evm-balance [ADDR]                  Solde EVM (eth_getBalance)
    evm-nonce [ADDR]                    Nonce EVM
    evm-call --to ADDR [--data HEX] [--value N]
    evm-sign --to ADDR --value N [--data HEX]
             [--tx-type legacy|2930|1559] [--gas N]
             Produit une tx EVM signée (hex) sans broadcaster

GESTION DU KEYFILE:
    keyfile-encrypt                     Chiffre le keyfile (v1 → v2, Argon2id)
    keyfile-decrypt                     Déchiffre le keyfile (v2 → v1, ⚠️ clair)
    keyfile-info                        Affiche les métadonnées sans déchiffrer

SÉCURITÉ:
    La passphrase peut être fournie via $SANGO_WALLET_PASSPHRASE
    (recommandé : utiliser le prompt interactif).

OPTIONS GLOBALES:
    --rpc URL                 Endpoint RPC (défaut : 127.0.0.1:8545)
    --keyfile PATH            Chemin du keyfile (défaut : ~/.sango/wallet.json)
    --rpc-tls-ca PATH         CA custom TLS (DER). Active HTTPS.
    --rpc-tls-insecure        Accepte tout cert TLS (devnet uniquement)
    --help, -h                Affiche cette aide
";

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_simple_command() {
        let (opts, cmd, rest) = parse_args(&s(&["balance"])).unwrap();
        assert!(opts.rpc.is_none());
        assert_eq!(cmd, "balance");
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_with_global_opts() {
        let (opts, cmd, _) = parse_args(&s(&[
            "--rpc",
            "1.2.3.4:9999",
            "--keyfile",
            "/tmp/k.json",
            "info",
        ]))
        .unwrap();
        assert_eq!(opts.rpc.as_deref(), Some("1.2.3.4:9999"));
        assert_eq!(opts.keyfile.as_deref(), Some("/tmp/k.json"));
        assert_eq!(cmd, "info");
    }

    #[test]
    fn parse_flags_and_require() {
        let f = parse_flags(&s(&["--to", "0xaa", "--amount", "1.5"])).unwrap();
        assert_eq!(require_flag(&f, "to").unwrap(), "0xaa");
        assert_eq!(require_flag(&f, "amount").unwrap(), "1.5");
        assert!(require_flag(&f, "missing").is_err());
    }

    #[test]
    fn unknown_option_rejected() {
        let err = parse_args(&s(&["--bogus", "x"])).unwrap_err();
        assert!(matches!(err, WalletError::Usage(_)));
    }
}
