//! Configuration du service P2P.

use std::time::Duration;

use libp2p::Multiaddr;

/// Configuration du service P2P.
#[derive(Debug, Clone)]
pub struct P2pConfig {
    /// Adresses d'écoute (par exemple `/ip4/0.0.0.0/udp/9000/quic-v1`).
    pub listen_addrs: Vec<Multiaddr>,
    /// Adresses bootstrap (peers à contacter au démarrage).
    pub bootstrap_addrs: Vec<(Multiaddr, libp2p::PeerId)>,
    /// Activer la découverte locale via mDNS (devnet uniquement).
    pub mdns_enabled: bool,
    /// Taille maximale d'un message gossipsub (bytes).
    pub max_message_size: usize,
    /// Heartbeat gossipsub.
    pub gossipsub_heartbeat: Duration,
}

impl Default for P2pConfig {
    fn default() -> Self {
        Self {
            listen_addrs: vec!["/ip4/127.0.0.1/udp/0/quic-v1"
                .parse()
                .expect("hardcoded addr")],
            bootstrap_addrs: Vec::new(),
            mdns_enabled: false,
            max_message_size: 4 * 1024 * 1024, // 4 MiB (bloc max 2 MiB + overhead)
            gossipsub_heartbeat: Duration::from_secs(1),
        }
    }
}

impl P2pConfig {
    /// Config devnet : mDNS activé, écoute sur localhost avec port OS-assigné.
    #[must_use]
    pub fn devnet() -> Self {
        Self {
            mdns_enabled: true,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_listen_is_valid() {
        let cfg = P2pConfig::default();
        assert_eq!(cfg.listen_addrs.len(), 1);
        assert!(!cfg.mdns_enabled);
    }

    #[test]
    fn devnet_enables_mdns() {
        let cfg = P2pConfig::devnet();
        assert!(cfg.mdns_enabled);
    }
}
