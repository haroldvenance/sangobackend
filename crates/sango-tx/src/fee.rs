//! Calcul des frais, overflow-safe.
//!
//! Formules normatives (Freeze, sections 27 et 29) :
//!
//! ```text
//! effective_gas_price = min(max_fee, base_fee + priority_fee)
//! total_fee = gas_used * effective_gas_price
//! validator_fee = total_fee * 9000 / 10000
//! burn_fee      = total_fee - validator_fee
//! ```
//!
//! Tous les calculs sont effectués en entiers avec vérification de
//! débordement. Un débordement rend la transaction invalide.

use sango_types::Transaction;

/// Prix effectif par unité de gas.
///
/// Retourne `None` si `base_fee + priority_fee` déborde `u128`.
#[must_use]
pub fn effective_gas_price(base_fee: u128, tx: &Transaction) -> Option<u128> {
    let cap = base_fee.checked_add(tx.priority_fee)?;
    Some(tx.max_fee.min(cap))
}

/// `gas_used * effective_gas_price`, overflow-safe.
///
/// Retourne `None` si le produit dépasse `u128::MAX`.
#[must_use]
pub fn total_fee(gas_used: u64, effective_price: u128) -> Option<u128> {
    (gas_used as u128).checked_mul(effective_price)
}

/// Répartit un `total_fee` en `(validator_share, burn_share)`.
///
/// La somme des deux parts vaut exactement `total`.
///
/// Le calcul évite tout débordement intermédiaire en travaillant sur
/// `total / 10` puis en ajustant pour le reste.
#[must_use]
pub fn split_fee(total: u128) -> (u128, u128) {
    // validator = total * 9000 / 10000 = total * 9 / 10
    let q = total / 10;
    let r = total % 10;
    let validator = q * 9 + (r * 9) / 10;
    let burn = total - validator;
    (validator, burn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sango_primitives::{Amount, ChainId32, NativeAddress, Signature};
    use sango_types::TxKind;

    fn tx(max_fee: u128, priority_fee: u128) -> Transaction {
        Transaction {
            version: 1,
            chain_id: ChainId32::from_bytes([0x11; 32]),
            nonce: 0,
            sender: NativeAddress::from_bytes([0xaa; 20]),
            public_key: None,
            gas_limit: 21_000,
            max_fee,
            priority_fee,
            value: Amount::from_base_units(0),
            tx_kind: TxKind::Transfer,
            recipient: Some(NativeAddress::from_bytes([0xbb; 20])),
            data: Vec::new(),
            signature: Signature::ZERO,
        }
    }

    #[test]
    fn effective_price_is_min_of_two() {
        assert_eq!(effective_gas_price(10, &tx(20, 2)), Some(12));
        assert_eq!(effective_gas_price(10, &tx(5, 2)), Some(5));
        assert_eq!(effective_gas_price(10, &tx(12, 2)), Some(12));
    }

    #[test]
    fn effective_price_overflow() {
        assert_eq!(effective_gas_price(u128::MAX, &tx(u128::MAX, 1)), None);
    }

    #[test]
    fn total_fee_basic() {
        assert_eq!(total_fee(21_000, 12), Some(252_000));
    }

    #[test]
    fn total_fee_zero_gas() {
        assert_eq!(total_fee(0, 100), Some(0));
    }

    #[test]
    fn total_fee_overflow() {
        assert_eq!(total_fee(u64::MAX, u128::MAX), None);
    }

    #[test]
    fn split_fee_exact() {
        assert_eq!(split_fee(600_000), (540_000, 60_000));
    }

    #[test]
    fn split_fee_rounds_down_validator() {
        let (v, b) = split_fee(10_001);
        assert_eq!(v, 9_000);
        assert_eq!(b, 1_001);
        assert_eq!(v + b, 10_001);
    }

    #[test]
    fn split_fee_tiny() {
        assert_eq!(split_fee(0), (0, 0));
        assert_eq!(split_fee(1), (0, 1));
        assert_eq!(split_fee(9), (8, 1));
        assert_eq!(split_fee(10), (9, 1));
    }

    #[test]
    fn split_fee_never_overflows() {
        let (v, b) = split_fee(u128::MAX);
        assert_eq!(v + b, u128::MAX);
    }

    #[test]
    fn split_fee_is_deterministic() {
        for n in [0u128, 1, 9, 10, 11, 100, 10_000, 1_000_000_000] {
            assert_eq!(split_fee(n), split_fee(n));
        }
    }
}
