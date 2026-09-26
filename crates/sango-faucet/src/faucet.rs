//! Logique du faucet : rate limit + envoi de tx.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use sango_crypto::derive_native_address;
use sango_primitives::{Amount, NativeAddress, Signature};
use sango_types::{Transaction, TxKind};
use sango_wallet::commands::{fetch_account, fetch_chain_id, send_transaction};
use sango_wallet::rpc_client::RpcClient;
use sango_wallet::WalletError;

use crate::config::Config;

/// Erreur produite par un drip.
#[derive(Debug, thiserror::Error)]
pub enum FaucetError {
    /// Cooldown par adresse non écoulé.
    #[error("rate limited: retry in {remaining_secs}s")]
    RateLimited {
        /// Secondes restantes.
        remaining_secs: u64,
    },
    /// Limite par IP atteinte.
    #[error("rate limited per IP")]
    RateLimitedPerIp,
    /// Erreur wallet (RPC, signature…).
    #[error("wallet: {0}")]
    Wallet(#[from] WalletError),
}

/// Faucet.
pub struct Faucet {
    config: Config,
    rpc: RpcClient,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    /// Timestamp du dernier drip par adresse.
    last_per_address: HashMap<NativeAddress, u64>,
    /// Sliding window des drips par IP.
    requests_per_ip: HashMap<IpAddr, Vec<u64>>,
}

impl Faucet {
    /// Crée un faucet prêt à servir.
    #[must_use]
    pub fn new(config: Config) -> Self {
        let rpc = RpcClient::new(&config.rpc_url);
        Self {
            config,
            rpc,
            state: Mutex::new(State::default()),
        }
    }

    /// Adresse native du faucet.
    #[must_use]
    pub fn faucet_address(&self) -> NativeAddress {
        derive_native_address(&self.config.faucet_keypair.public_key())
    }

    /// Montant d'un drip (base units).
    #[must_use]
    pub fn amount_base_units(&self) -> u128 {
        self.config.amount_base_units
    }

    /// Cooldown (secondes).
    #[must_use]
    pub fn cooldown_secs(&self) -> u64 {
        self.config.cooldown_secs
    }

    /// Adresse d'écoute HTTP.
    #[must_use]
    pub fn config_listen_addr(&self) -> std::net::SocketAddr {
        self.config.listen_addr
    }

    /// Solde actuel du faucet (base units).
    pub fn balance_base_units(&self) -> Result<u128, FaucetError> {
        let addr = self.faucet_address();
        let (_, balance, _) = fetch_account(&self.rpc, &addr).map_err(FaucetError::Wallet)?;
        Ok(balance)
    }

    /// Demande un drip vers `to`.
    ///
    /// ## Rate limiting
    ///
    /// 1. **Par adresse** : un même `to` ne peut redemander qu'après
    ///    `cooldown_secs`.
    /// 2. **Par IP** : une même IP ne peut faire plus de
    ///    `max_requests_per_ip` drips sur `cooldown_secs`.
    pub fn request(&self, to: NativeAddress, peer: Option<IpAddr>) -> Result<String, FaucetError> {
        let now = now_unix();

        // 1. Rate limit.
        {
            let mut state = self.state.lock().expect("faucet state mutex poisoned");

            if let Some(&last) = state.last_per_address.get(&to) {
                let elapsed = now.saturating_sub(last);
                if elapsed < self.config.cooldown_secs {
                    return Err(FaucetError::RateLimited {
                        remaining_secs: self.config.cooldown_secs - elapsed,
                    });
                }
            }

            if let Some(ip) = peer {
                let window = state.requests_per_ip.entry(ip).or_default();
                window.retain(|t| now.saturating_sub(*t) < self.config.cooldown_secs);
                if window.len() as u32 >= self.config.max_requests_per_ip {
                    return Err(FaucetError::RateLimitedPerIp);
                }
                window.push(now);
            }

            state.last_per_address.insert(to, now);
        }

        // 2. Envoi de la tx.
        self.send_tx(to)
    }

    fn send_tx(&self, to: NativeAddress) -> Result<String, FaucetError> {
        let chain_id = fetch_chain_id(&self.rpc).map_err(FaucetError::Wallet)?;
        let from = self.faucet_address();
        let (nonce, _balance, onchain_pk) =
            fetch_account(&self.rpc, &from).map_err(FaucetError::Wallet)?;

        let declare_pk = if onchain_pk.is_none() {
            Some(self.config.faucet_keypair.public_key())
        } else {
            None
        };

        let tx = Transaction {
            version: sango_types::PROTOCOL_VERSION_V1,
            chain_id,
            nonce,
            sender: from,
            public_key: declare_pk,
            gas_limit: 21_000,
            max_fee: self.config.max_fee_base_units,
            priority_fee: 0,
            value: Amount::from_base_units(self.config.amount_base_units),
            tx_kind: TxKind::Transfer,
            recipient: Some(to),
            data: Vec::new(),
            signature: Signature::ZERO,
        };
        let signed = tx.sign(&self.config.faucet_keypair);

        send_transaction(&self.rpc, &signed).map_err(FaucetError::Wallet)
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sango_primitives::Amount;

    fn dummy_config() -> Config {
        Config {
            rpc_url: "http://127.0.0.1:0".to_string(), // jamais joignable
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            faucet_keypair: sango_crypto::NativeKeypair::from_seed([0x01; 32]),
            amount_base_units: 100 * 10_000_000,
            cooldown_secs: 3600,
            max_requests_per_ip: 2,
            max_fee_base_units: 1000,
        }
    }

    #[test]
    fn faucet_address_is_derived() {
        let f = Faucet::new(dummy_config());
        let expected = derive_native_address(&f.config.faucet_keypair.public_key());
        assert_eq!(f.faucet_address(), expected);
    }

    #[test]
    fn rate_limit_per_address() {
        let f = Faucet::new(dummy_config());
        let to = NativeAddress::from_bytes([0xaa; 20]);

        // 1er appel : passe le rate limit (échoue sur l'envoi RPC).
        let r1 = f.request(to, None);
        assert!(matches!(r1, Err(FaucetError::Wallet(_))), "got {r1:?}");

        // 2e appel immédiat : rate limited.
        let r2 = f.request(to, None);
        assert!(
            matches!(r2, Err(FaucetError::RateLimited { .. })),
            "got {r2:?}"
        );
    }

    #[test]
    fn rate_limit_per_ip() {
        let f = Faucet::new(dummy_config());
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // IP limit = 2. On fait 2 drips (adresses distinctes).
        let _ = f.request(NativeAddress::from_bytes([0x01; 20]), Some(ip));
        let _ = f.request(NativeAddress::from_bytes([0x02; 20]), Some(ip));

        // 3e : IP limitée.
        let r3 = f.request(NativeAddress::from_bytes([0x03; 20]), Some(ip));
        assert!(
            matches!(r3, Err(FaucetError::RateLimitedPerIp)),
            "got {r3:?}"
        );
    }

    #[test]
    fn different_ips_have_separate_budgets() {
        let f = Faucet::new(dummy_config());
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        let _ = f.request(NativeAddress::from_bytes([0x01; 20]), Some(ip1));
        let _ = f.request(NativeAddress::from_bytes([0x02; 20]), Some(ip1));
        // ip2 a son propre budget.
        let r = f.request(NativeAddress::from_bytes([0x03; 20]), Some(ip2));
        assert!(
            !matches!(r, Err(FaucetError::RateLimitedPerIp)),
            "got {r:?}"
        );
    }

    // Marqueur anti-warning.
    #[allow(dead_code)]
    fn _marker() {
        let _ = Amount::ZERO;
    }
}
