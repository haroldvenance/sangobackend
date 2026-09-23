//! Commandes du wallet.

use sango_codec::Encode;
use sango_primitives::{Amount, ChainId32, NativeAddress, Signature};
use sango_types::{Transaction, TxKind};

use crate::error::WalletError;
use crate::keystore::KeyFile;
use crate::rpc_client::RpcClient;

/// Convertit un montant "humain" (ex. `1.5`) en base units (`u128`).
///
/// Accepte `"100"`, `"1.5"`, `"0.0000001"`. Refuse plus de 7 décimales.
pub fn parse_sango_decimal(s: &str) -> Result<u128, WalletError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(WalletError::InvalidAmount("empty".into()));
    }
    let (int_part, frac_part) = match s.split_once('.') {
        Some((i, f)) => (i, f),
        None => (s, ""),
    };

    // Accepter uniquement des chiffres.
    for c in int_part.chars() {
        if !c.is_ascii_digit() {
            return Err(WalletError::InvalidAmount(format!("non-digit: {c}")));
        }
    }
    for c in frac_part.chars() {
        if !c.is_ascii_digit() {
            return Err(WalletError::InvalidAmount(format!("non-digit: {c}")));
        }
    }

    let int: u128 = if int_part.is_empty() {
        0
    } else {
        int_part
            .parse()
            .map_err(|e| WalletError::InvalidAmount(format!("{e}")))?
    };

    let mut frac_padded = frac_part.to_string();
    if frac_padded.len() > 7 {
        return Err(WalletError::InvalidAmount(format!(
            "too many decimals: {} (max 7)",
            frac_padded.len()
        )));
    }
    while frac_padded.len() < 7 {
        frac_padded.push('0');
    }
    let frac: u128 = if frac_padded.is_empty() {
        0
    } else {
        frac_padded
            .parse()
            .map_err(|e| WalletError::InvalidAmount(format!("{e}")))?
    };

    int.checked_mul(10_000_000)
        .and_then(|v| v.checked_add(frac))
        .ok_or_else(|| WalletError::InvalidAmount("overflow".into()))
}

/// Formate des base units en chaîne SANGO lisible.
#[must_use]
pub fn format_base_units(u: u128) -> String {
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

/// Lit le nonce et le solde d'une adresse via RPC.
///
/// Retourne `(nonce, balance_base_units)`. Si le compte n'existe pas,
/// retourne `(0, 0)`.
pub fn fetch_account(rpc: &RpcClient, address: &NativeAddress) -> Result<(u64, u128), WalletError> {
    let result = rpc.call(
        "sango_getAccount",
        serde_json::json!([format!("0x{}", address.to_hex())]),
    )?;
    if result.is_null() {
        return Ok((0, 0));
    }
    let nonce = result.get("nonce").and_then(|v| v.as_u64()).unwrap_or(0);
    let balance = result
        .get("balance")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u128>().ok())
        .unwrap_or(0);
    Ok((nonce, balance))
}

/// Paramètres de construction d'une transaction.
pub struct TxParams {
    /// Chaîne cible.
    pub chain_id: ChainId32,
    /// Nonce à utiliser.
    pub nonce: u64,
    /// Gaz limite.
    pub gas_limit: u64,
    /// `max_fee` (base units).
    pub max_fee: u128,
    /// `priority_fee` (base units).
    pub priority_fee: u128,
    /// Montant transféré (base units).
    pub value: Amount,
    /// Type.
    pub tx_kind: TxKind,
    /// Destinataire.
    pub recipient: Option<NativeAddress>,
    /// Données.
    pub data: Vec<u8>,
}

impl TxParams {
    /// Construit et signe la transaction.
    pub fn build_and_sign(self, kf: &KeyFile) -> Result<Transaction, WalletError> {
        let kp = kf.keypair()?;
        let sender = kf.address()?;
        let chain_id = self.chain_id;

        let mut tx = Transaction {
            version: sango_types::PROTOCOL_VERSION_V1,
            chain_id,
            nonce: self.nonce,
            sender,
            public_key: None, // déjà enregistrée normalement
            gas_limit: self.gas_limit,
            max_fee: self.max_fee,
            priority_fee: self.priority_fee,
            value: self.value,
            tx_kind: self.tx_kind,
            recipient: self.recipient,
            data: self.data,
            signature: Signature::ZERO,
        };
        tx = tx.sign(&kp);
        Ok(tx)
    }
}

/// Envoie une transaction signée via RPC et retourne son hash.
pub fn send_transaction(rpc: &RpcClient, tx: &Transaction) -> Result<String, WalletError> {
    let bytes = tx.encode_to_vec();
    let hex_str = format!("0x{}", hex::encode(&bytes));
    let result = rpc.call("sango_sendTransaction", serde_json::json!([hex_str]))?;
    result
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| WalletError::Rpc("sendTransaction: expected string".into()))
}

/// Récupère le chain_id du nœud.
pub fn fetch_chain_id(rpc: &RpcClient) -> Result<ChainId32, WalletError> {
    let result = rpc.call("sango_chainId", serde_json::json!([]))?;
    let s = result
        .as_str()
        .ok_or_else(|| WalletError::Rpc("chainId: expected string".into()))?;
    ChainId32::from_hex(s).map_err(|e| WalletError::Rpc(format!("bad chainId: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_decimal_integers() {
        assert_eq!(parse_sango_decimal("0").unwrap(), 0);
        assert_eq!(parse_sango_decimal("1").unwrap(), 10_000_000);
        assert_eq!(parse_sango_decimal("100").unwrap(), 1_000_000_000);
    }

    #[test]
    fn parse_decimal_fractions() {
        assert_eq!(parse_sango_decimal("0.5").unwrap(), 5_000_000);
        assert_eq!(parse_sango_decimal("1.2345678").unwrap(), 12_345_678);
        assert_eq!(parse_sango_decimal(".5").unwrap(), 5_000_000);
    }

    #[test]
    fn parse_decimal_too_many_decimals() {
        assert!(parse_sango_decimal("1.12345678").is_err());
    }

    #[test]
    fn parse_decimal_invalid() {
        assert!(parse_sango_decimal("abc").is_err());
        assert!(parse_sango_decimal("1.2.3").is_err());
        assert!(parse_sango_decimal("").is_err());
    }

    #[test]
    fn format_units() {
        assert_eq!(format_base_units(0), "0");
        assert_eq!(format_base_units(10_000_000), "1");
        assert_eq!(format_base_units(5_000_000), "0.5");
        assert_eq!(format_base_units(12_345_678), "1.2345678");
    }

    #[test]
    fn format_parse_roundtrip() {
        for s in ["0", "1", "100", "0.5", "1.2345678"] {
            let u = parse_sango_decimal(s).unwrap();
            assert_eq!(format_base_units(u), s);
        }
    }
}
