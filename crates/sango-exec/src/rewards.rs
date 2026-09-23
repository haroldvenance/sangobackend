//! Distribution des récompenses PoS.
//!
//! Freeze section 9 : pool maximal de 150 000 000 SANGO réparti sur 5 ans.
//!
//! ## Formule
//!
//! ```text
//! total = block_reward(height)  (plafonné au restant du pool)
//! commission = total * commission_bps / 10000
//! after_commission = total - commission
//!
//! validator_from_stake = after_commission * self_stake / total_stake
//! delegator_portion    = after_commission - validator_from_stake
//!
//! pour chaque délégation d vers le validateur :
//!     share(d) = delegator_portion * bonded(d) / total_delegated
//!     crédit pending_rewards(d) += share(d)
//!
//! reste (arrondi) → validateur
//! crédit compte validateur += commission + validator_from_stake + reste
//! ```

use sango_primitives::{Amount, NativeAddress};
use sango_state::NativeState;
use sango_types::ValidatorInfo;

use crate::error::ApplyError;
use crate::ExecutionContext;

/// Nombre de blocs par année (365,25 j × 86400 s / 5 s).
pub const BLOCKS_PER_YEAR: u64 = 6_311_520;

/// Nombre d'années du programme de récompenses.
pub const REWARD_YEARS: usize = 5;

/// Budget annuel en SANGO (45M, 37.5M, 30M, 22.5M, 15M).
const ANNUAL_BUDGETS_SANGO: [u128; REWARD_YEARS] =
    [45_000_000, 37_500_000, 30_000_000, 22_500_000, 15_000_000];

/// Conversion SANGO → base units (10^7).
const BASE_UNITS_PER_SANGO: u128 = 10_000_000;

/// Budget annuel converti en base units.
#[must_use]
pub fn annual_budget_base(year_index: usize) -> Option<u128> {
    ANNUAL_BUDGETS_SANGO
        .get(year_index)
        .map(|sango| sango.saturating_mul(BASE_UNITS_PER_SANGO))
}

/// Pool maximal de récompenses PoS (150 M SANGO en base units).
#[must_use]
pub fn max_pos_rewards() -> Amount {
    Amount::from_base_units(150_000_000 * BASE_UNITS_PER_SANGO)
}

/// Récompense par bloc pour une hauteur donnée.
#[must_use]
pub fn block_reward(height: u64) -> Amount {
    let year_index = (height / BLOCKS_PER_YEAR) as usize;
    let Some(budget) = annual_budget_base(year_index) else {
        return Amount::ZERO;
    };
    Amount::from_base_units(budget / BLOCKS_PER_YEAR as u128)
}

/// Détail d'une distribution de récompense.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RewardDistribution {
    /// Récompense totale du bloc (base units).
    pub total: Amount,
    /// Part totale versée au compte du validateur (commission + self-stake + arrondi).
    pub validator_share: Amount,
    /// Part versée aux délégateurs (cumulé, base units).
    pub delegators_share: Amount,
    /// Nombre de délégations créditées.
    pub delegations_credited: usize,
}

/// Distribue la récompense d'un bloc au validateur proposant.
///
/// Retourne `None` si les récompenses sont désactivées, si la 5ᵉ année est
/// dépassée, ou si le pool maximal est épuisé.
pub fn distribute_block_rewards(
    state: &mut NativeState,
    proposer: NativeAddress,
    ctx: &ExecutionContext,
) -> Result<Option<RewardDistribution>, ApplyError> {
    if !ctx.rewards_enabled {
        return Ok(None);
    }

    // 1. Budget brut du bloc.
    let reward = block_reward(ctx.current_height);
    if reward.is_zero() {
        return Ok(None);
    }

    // 2. Plafond global.
    let distributed = state.total_pos_rewards();
    let max = max_pos_rewards();
    if distributed >= max {
        return Ok(None);
    }
    let remaining = max.base_units() - distributed.base_units();
    let capped = reward.base_units().min(remaining);
    if capped == 0 {
        return Ok(None);
    }
    let total = Amount::from_base_units(capped);
    let total_u = total.base_units();

    // 3. Validateur.
    let info: ValidatorInfo = state
        .get_validator(&proposer)
        .ok_or(ApplyError::ValidatorNotFound(proposer))?;

    // 3a. Commission.
    let commission_bps = info.commission_bps as u128;
    let commission = total_u.saturating_mul(commission_bps) / 10_000;
    let after_commission = total_u.saturating_sub(commission);

    // 3b. Répartition de `after_commission` au prorata du stake.
    let self_stake = info.self_stake.base_units();
    let total_delegated = info.total_delegated.base_units();
    let total_stake = self_stake.saturating_add(total_delegated);

    let validator_from_stake = if total_stake == 0 {
        // Ne devrait jamais arriver (le validateur existe avec self_stake
        // > 0), mais on le gère par sécurité : tout va au validateur.
        after_commission
    } else {
        after_commission
            .saturating_mul(self_stake)
            .checked_div(total_stake)
            .unwrap_or(0)
    };
    let delegator_portion = after_commission.saturating_sub(validator_from_stake);

    // 4. Distribution aux délégateurs au prorata du total délégué.
    let mut paid_to_delegators: u128 = 0;
    let mut delegations_credited: usize = 0;
    if total_delegated > 0 && delegator_portion > 0 {
        for mut d in state.delegations_for(&proposer) {
            let bonded = d.bonded.base_units();
            if bonded == 0 {
                continue;
            }
            let share = delegator_portion
                .saturating_mul(bonded)
                .checked_div(total_delegated)
                .unwrap_or(0);
            if share == 0 {
                continue;
            }
            d.pending_rewards = d
                .pending_rewards
                .checked_add(Amount::from_base_units(share))
                .ok_or(ApplyError::TotalFeeOverflow)?;
            state.set_delegation(d);
            delegations_credited += 1;
            paid_to_delegators = paid_to_delegators.saturating_add(share);
        }
    }

    // 5. Arrondi → validateur.
    let rounding = delegator_portion.saturating_sub(paid_to_delegators);
    let to_validator = commission
        .saturating_add(validator_from_stake)
        .saturating_add(rounding);

    debug_assert_eq!(
        to_validator.saturating_add(paid_to_delegators),
        total_u,
        "répartition incohérente"
    );

    state
        .credit(proposer, Amount::from_base_units(to_validator))
        .map_err(ApplyError::State)?;

    // 6. Cumul global.
    state.add_pos_rewards(total).map_err(ApplyError::State)?;

    Ok(Some(RewardDistribution {
        total,
        validator_share: Amount::from_base_units(to_validator),
        delegators_share: Amount::from_base_units(paid_to_delegators),
        delegations_credited,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sango_crypto::{derive_native_address, NativeKeypair};
    use sango_primitives::{ChainId32, PublicKey};
    use sango_types::Delegation;

    fn chain() -> ChainId32 {
        ChainId32::from_bytes([0x11; 32])
    }

    fn ctx(height: u64, rewards_enabled: bool) -> ExecutionContext {
        ExecutionContext {
            chain_id: chain(),
            base_fee: 10,
            fee_recipient: NativeAddress::from_bytes([0xef; 20]),
            initial_supply: Amount::from_sango(1_000_000_000).unwrap(),
            current_time: 1_700_000_000,
            current_height: height,
            rewards_enabled,
        }
    }

    fn validator_info(
        addr: NativeAddress,
        pk: PublicKey,
        self_stake: u128,
        commission_bps: u32,
    ) -> ValidatorInfo {
        ValidatorInfo {
            address: addr,
            public_key: pk,
            self_stake: Amount::from_sango(self_stake).unwrap(),
            total_delegated: Amount::ZERO,
            commission_bps,
            pending_commission_bps: None,
            pending_commission_at: None,
            jailed: false,
            jailed_until: None,
        }
    }

    // --- block_reward -------------------------------------------------------

    #[test]
    fn block_reward_year_1() {
        let r = block_reward(0);
        let expected_budget = 45_000_000u128 * BASE_UNITS_PER_SANGO;
        let expected = expected_budget / BLOCKS_PER_YEAR as u128;
        assert_eq!(r.base_units(), expected);
        assert!(r.base_units() > 0);
    }

    #[test]
    fn block_reward_year_2() {
        let r1 = block_reward(0);
        let r2 = block_reward(BLOCKS_PER_YEAR);
        assert!(r2.base_units() < r1.base_units());
        assert!(r2.base_units() > 0);
    }

    #[test]
    fn block_reward_year_5() {
        let r = block_reward(4 * BLOCKS_PER_YEAR);
        assert!(r.base_units() > 0);
    }

    #[test]
    fn block_reward_after_5_years_is_zero() {
        let r = block_reward(5 * BLOCKS_PER_YEAR);
        assert!(r.is_zero());
    }

    #[test]
    fn block_reward_sums_to_less_than_budget() {
        let mut total: u128 = 0;
        for year in 0..REWARD_YEARS {
            let r = block_reward(year as u64 * BLOCKS_PER_YEAR);
            total = total.saturating_add(r.base_units().saturating_mul(BLOCKS_PER_YEAR as u128));
        }
        assert!(total <= 150_000_000u128 * BASE_UNITS_PER_SANGO);
    }

    // --- distribute_block_rewards ------------------------------------------

    #[test]
    fn rewards_disabled_returns_none() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let addr = derive_native_address(&kp.public_key());
        let mut state = NativeState::new();
        state.set_validator(validator_info(addr, kp.public_key(), 100_000, 700));
        let r = distribute_block_rewards(&mut state, addr, &ctx(0, false)).unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn rewards_enabled_credits_validator() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let addr = derive_native_address(&kp.public_key());
        let mut state = NativeState::new();
        state.set_validator(validator_info(addr, kp.public_key(), 100_000, 700));

        let before = state.balance_of(&addr);
        let r = distribute_block_rewards(&mut state, addr, &ctx(0, true))
            .unwrap()
            .unwrap();
        let after = state.balance_of(&addr);

        assert!(after > before);
        assert_eq!(r.total, block_reward(0));
        // Sans délégation, tout va au validateur.
        assert_eq!(r.validator_share, r.total);
        assert_eq!(r.delegators_share, Amount::ZERO);
        assert_eq!(r.delegations_credited, 0);
    }

    #[test]
    fn rewards_split_with_delegators() {
        let validator_kp = NativeKeypair::from_seed([0x42; 32]);
        let delegator_kp = NativeKeypair::from_seed([0x01; 32]);
        let validator = derive_native_address(&validator_kp.public_key());
        let delegator = derive_native_address(&delegator_kp.public_key());

        let mut state = NativeState::new();
        let mut info = validator_info(validator, validator_kp.public_key(), 100_000, 700);
        info.total_delegated = Amount::from_sango(100_000).unwrap();
        state.set_validator(info);

        let mut d = Delegation::empty(delegator, validator);
        d.bonded = Amount::from_sango(100_000).unwrap();
        state.set_delegation(d);

        let r = distribute_block_rewards(&mut state, validator, &ctx(0, true))
            .unwrap()
            .unwrap();

        // Vérifie la cohérence du split.
        assert_eq!(
            r.validator_share.base_units() + r.delegators_share.base_units(),
            r.total.base_units()
        );
        assert!(r.delegators_share.base_units() > 0);
        assert_eq!(r.delegations_credited, 1);

        let d_after = state.get_delegation(&delegator, &validator).unwrap();
        assert_eq!(d_after.pending_rewards, r.delegators_share);
    }

    #[test]
    fn rewards_split_is_consistent_with_commission() {
        // Vérifie les montants exacts avec commission 700 bps, stakes 50/50.
        let validator_kp = NativeKeypair::from_seed([0x42; 32]);
        let delegator_kp = NativeKeypair::from_seed([0x01; 32]);
        let validator = derive_native_address(&validator_kp.public_key());
        let delegator = derive_native_address(&delegator_kp.public_key());

        let mut state = NativeState::new();
        let mut info = validator_info(validator, validator_kp.public_key(), 100_000, 700);
        info.total_delegated = Amount::from_sango(100_000).unwrap();
        state.set_validator(info);

        let mut d = Delegation::empty(delegator, validator);
        d.bonded = Amount::from_sango(100_000).unwrap();
        state.set_delegation(d);

        let r = distribute_block_rewards(&mut state, validator, &ctx(0, true))
            .unwrap()
            .unwrap();

        let total = r.total.base_units();
        let commission = total * 700 / 10_000;
        let after_commission = total - commission;
        // 50/50 → validator_from_stake = after_commission / 2
        let validator_from_stake = after_commission / 2;
        let expected_validator = commission + validator_from_stake;
        let expected_delegators = after_commission - validator_from_stake;

        assert_eq!(r.validator_share.base_units(), expected_validator);
        assert_eq!(r.delegators_share.base_units(), expected_delegators);
    }

    #[test]
    fn rewards_capped_at_max_pool() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let addr = derive_native_address(&kp.public_key());
        let mut state = NativeState::new();
        state.set_validator(validator_info(addr, kp.public_key(), 100_000, 700));

        let almost = max_pos_rewards();
        state.add_pos_rewards(almost).unwrap();

        let r = distribute_block_rewards(&mut state, addr, &ctx(0, true)).unwrap();
        assert!(r.is_none(), "pool épuisé → pas de distribution");
        assert_eq!(state.total_pos_rewards(), almost);
    }

    #[test]
    fn unknown_validator_rejected() {
        let mut state = NativeState::new();
        let addr = NativeAddress::from_bytes([0xee; 20]);
        let err = distribute_block_rewards(&mut state, addr, &ctx(0, true)).unwrap_err();
        assert!(matches!(err, ApplyError::ValidatorNotFound(_)));
    }

    #[test]
    fn total_pos_rewards_accumulates() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let addr = derive_native_address(&kp.public_key());
        let mut state = NativeState::new();
        state.set_validator(validator_info(addr, kp.public_key(), 100_000, 700));

        assert_eq!(state.total_pos_rewards(), Amount::ZERO);

        distribute_block_rewards(&mut state, addr, &ctx(0, true)).unwrap();
        let after_1 = state.total_pos_rewards();
        assert!(after_1.base_units() > 0);

        distribute_block_rewards(&mut state, addr, &ctx(1, true)).unwrap();
        let after_2 = state.total_pos_rewards();
        assert!(after_2 > after_1);
    }

    #[test]
    fn deterministic_rewards() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let addr = derive_native_address(&kp.public_key());

        let mut a = NativeState::new();
        a.set_validator(validator_info(addr, kp.public_key(), 100_000, 700));

        let mut b = NativeState::new();
        b.set_validator(validator_info(addr, kp.public_key(), 100_000, 700));

        for h in 0..100 {
            let ra = distribute_block_rewards(&mut a, addr, &ctx(h, true)).unwrap();
            let rb = distribute_block_rewards(&mut b, addr, &ctx(h, true)).unwrap();
            assert_eq!(ra, rb);
        }
        assert_eq!(a.native_state_root(), b.native_state_root());
    }
}
