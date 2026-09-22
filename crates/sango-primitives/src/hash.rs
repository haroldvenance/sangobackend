//! Hash de protocole (32 bytes).

use crate::bytes::define_fixed_bytes;

define_fixed_bytes!(
    Hash32,
    32,
    "Hash de protocole Sango (32 bytes), produit par Keccak-256 sur un payload \
     préfixé par un domain separator. Voir `SANGO PROTOCOL FREEZE V1`."
);

#[cfg(test)]
mod tests {
    use super::Hash32;
    use hex_literal::hex;

    #[test]
    fn len_is_32() {
        assert_eq!(Hash32::LEN, 32);
    }

    #[test]
    fn zero_is_zero() {
        assert!(Hash32::ZERO.is_zero());
    }

    #[test]
    fn roundtrip_bytes() {
        let raw: [u8; 32] = hex!(
            "0102030405060708090a0b0c0d0e0f10"
            "1112131415161718191a1b1c1d1e1f20"
        );
        let h = Hash32::from_bytes(raw);
        assert_eq!(h.to_bytes(), raw);
        assert_eq!(Hash32::from_slice(&raw).unwrap(), h);
    }

    #[test]
    fn hex_encoding_is_lowercase_no_prefix() {
        let h = Hash32::from_bytes([0xab; 32]);
        let s = h.to_hex();
        assert_eq!(s.len(), 64);
        assert!(s
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert!(!s.starts_with("0x"));
        assert_eq!(Hash32::from_hex(&s).unwrap(), h);
    }

    #[test]
    fn wrong_length_rejected() {
        assert!(Hash32::from_slice(&[0u8; 31]).is_err());
        assert!(Hash32::from_slice(&[0u8; 33]).is_err());
    }
}
