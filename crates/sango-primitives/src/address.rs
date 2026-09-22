//! Adresses natives et EVM (20 bytes chacune, namespaces distincts).

use crate::bytes::define_fixed_bytes;

define_fixed_bytes!(
    NativeAddress,
    20,
    "Adresse native Sango (20 bytes).\n\n\
     Dérivation :\n\
     ```text\n\
     native_address = Keccak256(\"SANGO/ADDRESS/V1\" || ed25519_public_key)[0:20]\n\
     ```\n\n\
     Affichage utilisateur : Bech32m, HRP `sango` (mainnet) ou `tsango` (testnet).\n\
     Ce type ne doit **jamais** être confondu avec [`EvmAddress`]."
);

define_fixed_bytes!(
    EvmAddress,
    20,
    "Adresse compatible EVM (20 bytes).\n\n\
     Dérivation : convention Ethereum standard à partir d'une clé publique \
     secp256k1 non compressée :\n\
     ```text\n\
     evm_address = Keccak256(uncompressed_pubkey_without_prefix)[12:32]\n\
     ```\n\n\
     Ce type ne doit **jamais** être confondu avec [`NativeAddress`]."
);

#[cfg(test)]
mod tests {
    use super::{EvmAddress, NativeAddress};

    #[test]
    fn both_are_20_bytes() {
        assert_eq!(NativeAddress::LEN, 20);
        assert_eq!(EvmAddress::LEN, 20);
    }

    #[test]
    fn roundtrip_native() {
        let raw = [0x11u8; 20];
        let a = NativeAddress::from_bytes(raw);
        assert_eq!(a.to_bytes(), raw);
        assert_eq!(NativeAddress::from_slice(&raw).unwrap(), a);
    }

    #[test]
    fn roundtrip_evm() {
        let raw = [0x22u8; 20];
        let a = EvmAddress::from_bytes(raw);
        assert_eq!(a.to_bytes(), raw);
        assert_eq!(EvmAddress::from_slice(&raw).unwrap(), a);
    }

    #[test]
    fn wrong_length_rejected() {
        assert!(NativeAddress::from_slice(&[0u8; 19]).is_err());
        assert!(NativeAddress::from_slice(&[0u8; 21]).is_err());
        assert!(EvmAddress::from_slice(&[0u8; 19]).is_err());
        assert!(EvmAddress::from_slice(&[0u8; 21]).is_err());
    }

    #[test]
    fn display_hex_20_bytes() {
        let a = NativeAddress::from_bytes([0xab; 20]);
        assert_eq!(a.to_hex().len(), 40);
    }
}
