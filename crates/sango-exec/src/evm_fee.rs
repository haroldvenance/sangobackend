//! Règle normative **unique** de calcul du prix effectif EVM.
//!
//! ## Formule
//!
//! ```text
//! effective_gas_price = min(max_fee, base_fee + priority_fee)
//! ```
//!
//! Contrainte : `max_fee >= base_fee`. Sinon la transaction ne peut pas
//! être incluse dans le bloc courant.
//!
//! ## Règle de localisation
//!
//! Ce calcul vit **exclusivement ici**. Ni `sango-evm`, ni `sango-node`
//! ne doivent le réimplémenter. Le bridge revm reçoit la valeur déjà
//! calculée via `TxEnvExtras::effective_gas_price`.

use sango_primitives::U256;
use thiserror::Error;

/// Erreur produite par le calcul du prix effectif EVM.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EvmFeeError {
    /// `max_fee` inférieur à la base fee courante.
    #[error("max_fee ({max_fee}) < base_fee ({base_fee})")]
    MaxFeeBelowBaseFee {
        /// `max_fee` déclaré par la transaction.
        max_fee: U256,
        /// Base fee courante du bloc.
        base_fee: U256,
    },
}

/// Calcule le prix effectif par unité de gas pour une transaction EVM.
///
/// # Erreurs
///
/// [`EvmFeeError::MaxFeeBelowBaseFee`] si `max_fee < base_fee`.
///
/// # Overflow
///
/// L'addition `base_fee + priority_fee` est faite en `saturating_add` :
/// un dépassement sature à `U256::MAX` au lieu de paniquer. Le `min`
/// subséquent borne le résultat à `max_fee`, donc le comportement reste
/// correct même en cas de saturation.
pub fn effective_gas_price(
    max_fee: U256,
    priority_fee: U256,
    base_fee: U256,
) -> Result<U256, EvmFeeError> {
    if max_fee < base_fee {
        return Err(EvmFeeError::MaxFeeBelowBaseFee { max_fee, base_fee });
    }
    let cap = base_fee.saturating_add(priority_fee);
    Ok(max_fee.min(cap))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(v: u64) -> U256 {
        U256::from(v)
    }

    #[test]
    fn price_capped_at_base_plus_priority() {
        // max_fee = 100, base = 10, priority = 5 → cap = 15, résultat = 15.
        assert_eq!(effective_gas_price(u(100), u(5), u(10)).unwrap(), u(15));
    }

    #[test]
    fn price_uses_max_fee_when_below_cap() {
        // max_fee = 12, base = 10, priority = 5 → cap = 15, résultat = 12.
        assert_eq!(effective_gas_price(u(12), u(5), u(10)).unwrap(), u(12));
    }

    #[test]
    fn price_exactly_at_cap() {
        assert_eq!(effective_gas_price(u(15), u(5), u(10)).unwrap(), u(15));
    }

    #[test]
    fn price_exactly_at_base_when_priority_zero() {
        assert_eq!(effective_gas_price(u(10), u(0), u(10)).unwrap(), u(10));
    }

    #[test]
    fn price_zero_when_max_fee_zero_and_base_zero() {
        assert_eq!(effective_gas_price(u(0), u(0), u(0)).unwrap(), u(0));
    }

    #[test]
    fn rejects_max_fee_below_base() {
        let err = effective_gas_price(u(5), u(1), u(10)).unwrap_err();
        assert!(matches!(err, EvmFeeError::MaxFeeBelowBaseFee { .. }));
    }

    #[test]
    fn no_panic_on_huge_values() {
        // saturating_add dans le cap → pas de panic.
        let _ = effective_gas_price(U256::MAX, U256::MAX, U256::MAX);
        let _ = effective_gas_price(U256::MAX, U256::MAX, U256::ZERO);
    }

    #[test]
    fn deterministic() {
        let a = effective_gas_price(u(100), u(5), u(10)).unwrap();
        let b = effective_gas_price(u(100), u(5), u(10)).unwrap();
        assert_eq!(a, b);
    }
}
