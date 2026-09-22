//! Tests d'intégration pour les propriétés canoniques du codec.

use sango_codec::{CodecError, Decode, Encode};
use sango_primitives::{
    Amount, ChainId32, Epoch, EvmAddress, EvmChainId, Hash32, Height, NativeAddress, Round,
};

fn roundtrip<T>(value: &T)
where
    T: Encode + Decode + PartialEq + core::fmt::Debug,
{
    let bytes = value.encode_to_vec();
    let decoded = T::decode_exact(&bytes).expect("decode must succeed");
    assert_eq!(&decoded, value, "roundtrip mismatch");
}

#[test]
fn roundtrip_integers() {
    roundtrip(&0u8);
    roundtrip(&255u8);
    roundtrip(&0u16);
    roundtrip(&u16::MAX);
    roundtrip(&0u32);
    roundtrip(&u32::MAX);
    roundtrip(&0u64);
    roundtrip(&u64::MAX);
    roundtrip(&0u128);
    roundtrip(&u128::MAX);
}

#[test]
fn roundtrip_fixed_arrays() {
    roundtrip(&[0u8; 0]);
    roundtrip(&[0u8; 1]);
    roundtrip(&[0xaa_u8; 32]);
    roundtrip(&[0xff_u8; 64]);
}

#[test]
fn roundtrip_vec_u8() {
    roundtrip(&Vec::<u8>::new());
    roundtrip(&vec![0u8]);
    roundtrip(&vec![0xaa_u8, 0xbb, 0xcc]);
    roundtrip(&vec![0u8; 1024]);
}

#[test]
fn roundtrip_vec_u32() {
    roundtrip(&Vec::<u32>::new());
    roundtrip(&vec![1u32, 2, 3]);
}

#[test]
fn roundtrip_option() {
    roundtrip(&Option::<u64>::None);
    roundtrip(&Some(42u64));
}

#[test]
fn roundtrip_primitives() {
    roundtrip(&Hash32::from_bytes([0x11; 32]));
    roundtrip(&ChainId32::from_bytes([0x22; 32]));
    roundtrip(&NativeAddress::from_bytes([0x33; 20]));
    roundtrip(&EvmAddress::from_bytes([0x44; 20]));
    roundtrip(&Height::new(123));
    roundtrip(&Round::new(0));
    roundtrip(&Epoch::new(u64::MAX));
    roundtrip(&EvmChainId::new(1));
    roundtrip(&Amount::from_base_units(10_000_000));
    roundtrip(&Amount::from_base_units(10_000_000_000_000_000));
}

#[test]
fn integers_are_injective() {
    let a = 1u64.encode_to_vec();
    let b = 2u64.encode_to_vec();
    assert_ne!(a, b);
    assert_eq!(a.len(), 8);
    assert_eq!(b.len(), 8);
}

#[test]
fn different_types_with_same_value_differ() {
    let a = 1u8.encode_to_vec();
    let b = 1u32.encode_to_vec();
    assert_ne!(a, b);
    assert_eq!(a.len(), 1);
    assert_eq!(b.len(), 4);
}

#[test]
fn vec_count_is_u32_le() {
    let v = vec![1u8, 2, 3];
    let bytes = v.encode_to_vec();
    assert_eq!(bytes, vec![0x03, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03]);
}

#[test]
fn option_none_is_single_zero_byte() {
    let bytes = Option::<u64>::None.encode_to_vec();
    assert_eq!(bytes, vec![0x00]);
}

#[test]
fn option_some_prefixed_with_one() {
    let bytes = Some(0x0102030405060708u64).encode_to_vec();
    assert_eq!(
        bytes,
        vec![0x01, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
    );
}

#[test]
fn reject_trailing_bytes() {
    let mut bytes = 1u64.encode_to_vec();
    bytes.push(0x00);
    let err = u64::decode_exact(&bytes).unwrap_err();
    assert!(matches!(err, CodecError::TrailingBytes { count: 1, .. }));
}

#[test]
fn reject_truncated() {
    let bytes = &[0x01, 0x02, 0x03];
    let err = u64::decode_exact(bytes).unwrap_err();
    assert!(matches!(err, CodecError::UnexpectedEof { .. }));
}

#[test]
fn reject_vec_length_overflow_remaining() {
    let bytes = [0x05, 0x00, 0x00, 0x00];
    let err = Vec::<u8>::decode_exact(&bytes).unwrap_err();
    assert!(matches!(err, CodecError::InvalidLength { declared: 5, .. }));
}

#[test]
fn reject_invalid_option_tag() {
    let bytes = [0x02];
    let err = Option::<u64>::decode_exact(&bytes).unwrap_err();
    assert!(matches!(err, CodecError::InvalidTag { tag: 2 }));
}

#[test]
fn u32_le_byte_order() {
    let bytes = 0x01020304u32.encode_to_vec();
    assert_eq!(bytes, vec![0x04, 0x03, 0x02, 0x01]);
}

#[test]
fn u64_le_byte_order() {
    let bytes = 0x0102030405060708u64.encode_to_vec();
    assert_eq!(bytes, vec![0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
}

#[test]
fn roundtrip_bool() {
    roundtrip(&false);
    roundtrip(&true);
}

#[test]
fn bool_encoding_is_one_byte() {
    assert_eq!(false.encode_to_vec(), vec![0x00]);
    assert_eq!(true.encode_to_vec(), vec![0x01]);
}

#[test]
fn reject_invalid_bool_tag() {
    let bytes = [0x02];
    let err = bool::decode_exact(&bytes).unwrap_err();
    assert!(matches!(err, CodecError::InvalidTag { tag: 2 }));
}
