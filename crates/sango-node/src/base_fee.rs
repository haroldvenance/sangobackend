//! Calcul EIP-1559 de la base fee.

use sango_types::BlockHeader;

/// Base fee initiale (avant tout bloc).
///
/// Constante normative V1 : `1 base unit / gas`.
pub const INITIAL_BASE_FEE: u128 = 1;

/// Base fee minimale absolue (jamais en dessous).
pub const MIN_BASE_FEE: u128 = 1;

/// Dénominateur de variation maximale (Freeze section 28).
pub const BASE_FEE_MAX_CHANGE_DENOMINATOR: u128 = 8;

/// Calcule la base fee pour un bloc à partir de son parent.
///
/// Formule EIP-1559 (Freeze section 28) :
///
/// ```text
/// target = parent_gas_limit / 2
/// if parent_gas_used == target:
///     new = parent_base_fee
/// elif parent_gas_used > target:
///     delta = parent_base_fee * (parent_gas_used - target) / target / 8
///     new = parent_base_fee + max(delta, 1)
/// else:
///     delta = parent_base_fee * (target - parent_gas_used) / target / 8
///     new = max(parent_base_fee - delta, 1)
/// ```
///
/// Tous les calculs sont en `u128`, overflow-safe par `saturating_mul`.
/// Le résultat est toujours `>= MIN_BASE_FEE`.
#[must_use]
pub fn next_base_fee(parent: &BlockHeader) -> u128 {
    let target = parent.gas_limit / 2;
    if target == 0 {
        // Cas dégénéré : gas_limit parent = 0 ou 1. On retourne la base fee
        // courante, mais jamais en dessous du minimum.
        return parent.base_fee.max(MIN_BASE_FEE);
    }

    let parent_used = parent.gas_used;
    let parent_fee = parent.base_fee;

    if parent_used == target {
        parent_fee.max(MIN_BASE_FEE)
    } else if parent_used > target {
        let diff = parent_used - target;
        let delta = parent_fee
            .saturating_mul(diff as u128)
            .saturating_div(target as u128)
            .saturating_div(BASE_FEE_MAX_CHANGE_DENOMINATOR)
            .max(1);
        parent_fee.saturating_add(delta)
    } else {
        let diff = target - parent_used;
        let delta = parent_fee
            .saturating_mul(diff as u128)
            .saturating_div(target as u128)
            .saturating_div(BASE_FEE_MAX_CHANGE_DENOMINATOR);
        parent_fee.saturating_sub(delta).max(MIN_BASE_FEE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sango_primitives::{ChainId32, Epoch, Hash32, Height, NativeAddress, Round};

    fn header(gas_used: u64, gas_limit: u64, base_fee: u128) -> BlockHeader {
        BlockHeader {
            version: 1,
            chain_id: ChainId32::from_bytes([0x11; 32]),
            epoch: Epoch::new(0),
            height: Height::new(1),
            round: Round::new(0),
            previous_block_hash: Hash32::ZERO,
            timestamp: 0,
            proposer_address: NativeAddress::from_bytes([0x00; 20]),
            transaction_root: Hash32::ZERO,
            state_root: Hash32::ZERO,
            receipt_root: Hash32::ZERO,
            gas_used,
            gas_limit,
            base_fee,
        }
    }

    #[test]
    fn at_target_keeps_base_fee() {
        // target = 15_000_000
        assert_eq!(next_base_fee(&header(15_000_000, 30_000_000, 100)), 100);
    }

    #[test]
    fn below_target_decreases() {
        // 0 gas used, target = 15_000_000
        // delta = 100 * 15_000_000 / 15_000_000 / 8 = 100/8 = 12
        // new = 100 - 12 = 88
        assert_eq!(next_base_fee(&header(0, 30_000_000, 100)), 88);
    }

    #[test]
    fn above_target_increases() {
        // gas_used = 30_000_000, target = 15_000_000
        // delta = 100 * 15_000_000 / 15_000_000 / 8 = 12
        // new = 112
        assert_eq!(next_base_fee(&header(30_000_000, 30_000_000, 100)), 112);
    }

    #[test]
    fn increase_has_min_delta_of_one() {
        // Petite variation : delta = 1 au minimum.
        // gas_used = 15_000_001, target = 15_000_000
        // delta_brut = 1 * 1 / 15_000_000 / 8 = 0 → max(1) = 1
        assert_eq!(next_base_fee(&header(15_000_001, 30_000_000, 1)), 2);
    }

    #[test]
    fn decrease_has_min_base_fee_of_one() {
        // base_fee = 1, used = 0 → new = max(1 - 0, 1) = 1
        assert_eq!(next_base_fee(&header(0, 30_000_000, 1)), 1);
    }

    #[test]
    fn max_theoretical_increase_is_12_5_percent() {
        // À parent_used = 2 * target (= gas_limit), le delta est
        //   base_fee * target / target / 8 = base_fee / 8
        // soit +12,5 %.
        let base = 1_000_000u128;
        let new = next_base_fee(&header(30_000_000, 30_000_000, base));
        assert_eq!(new, base + base / 8);
    }

    #[test]
    fn max_theoretical_decrease_is_12_5_percent() {
        // À parent_used = 0, delta = base_fee / 8.
        let base = 1_000_000u128;
        let new = next_base_fee(&header(0, 30_000_000, base));
        assert_eq!(new, base - base / 8);
    }

    #[test]
    fn does_not_overflow_on_huge_values() {
        // Doit retourner sans panic.
        let h = header(u64::MAX, u64::MAX, u128::MAX);
        let _ = next_base_fee(&h);
    }

    #[test]
    fn deterministic() {
        let h = header(20_000_000, 30_000_000, 500);
        assert_eq!(next_base_fee(&h), next_base_fee(&h));
    }

    #[test]
    fn zero_gas_limit_returns_current() {
        // Cas dégénéré : gas_limit = 0.
        let h = header(0, 0, 100);
        assert_eq!(next_base_fee(&h), 100);
    }
}
