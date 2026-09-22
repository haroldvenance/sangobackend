//! Identifiants de chaîne.

use crate::bytes::define_fixed_bytes;

define_fixed_bytes!(
    ChainId32,
    32,
    "Identifiant natif de réseau Sango (32 bytes).\n\n\
     Généré une seule fois par réseau (mainnet, testnet, devnet) et inscrit \
     explicitement dans le Genesis. Voir `SANGO PROTOCOL FREEZE V1`."
);

/// Identifiant EVM (chain ID `u64`), utilisé par EIP-155, EIP-1559, EIP-7702
/// et le RPC Ethereum.
///
/// Distinct du [`ChainId32`] natif : les deux vivent dans des namespaces
/// séparés et sont définis tous les deux dans le Genesis.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct EvmChainId(u64);

impl EvmChainId {
    /// Construit un identifiant EVM à partir d'un `u64`.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Retourne la valeur `u64` sous-jacente.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl From<u64> for EvmChainId {
    fn from(v: u64) -> Self {
        Self(v)
    }
}

impl From<EvmChainId> for u64 {
    fn from(v: EvmChainId) -> Self {
        v.0
    }
}

impl core::fmt::Display for EvmChainId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{ChainId32, EvmChainId};

    #[test]
    fn chain_id_32_bytes() {
        assert_eq!(ChainId32::LEN, 32);
        let id = ChainId32::from_bytes([0x42; 32]);
        assert_eq!(id.to_bytes()[0], 0x42);
    }

    #[test]
    fn evm_chain_id_roundtrip() {
        let id = EvmChainId::new(12345);
        assert_eq!(id.get(), 12345);
        let v: u64 = id.into();
        assert_eq!(v, 12345);
        assert_eq!(EvmChainId::from(12345_u64), id);
        assert_eq!(id.to_string(), "12345");
    }
}
