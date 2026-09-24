//! Finalisation des unbondings mûrs.
//!
//! À chaque bloc, on parcourt le namespace `Unbonding` et on libère les
//! fonds dont `mature_at <= ctx.current_time`. C'est **déterministe** :
//! `current_time` vient du header du bloc, donc tous les nœuds voient le
//! même timestamp.
//!
//! ## Ordre canonique
//!
//! Les événements sont traités par `id` croissant. L'ordre n'a pas
//! d'impact sur le `state_root` (les crédits sont commutatifs), mais il
//! garantit un comportement reproductible et facilite le debug.

use sango_primitives::{Amount, NativeAddress};
use sango_state::NativeState;

use crate::error::ApplyError;
use crate::ExecutionContext;

/// Détail d'un unbonding libéré.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleasedUnbonding {
    /// Identifiant de l'événement.
    pub id: u64,
    /// Compte crédité.
    pub delegator: NativeAddress,
    /// Validateur source.
    pub validator: NativeAddress,
    /// Montant libéré (base units).
    pub amount: Amount,
}

/// Rapport d'un passage de finalisation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UnbondingReport {
    /// Événements libérés lors de cet appel.
    pub released: Vec<ReleasedUnbonding>,
    /// Nombre d'événements encore en attente (non mûrs).
    pub still_pending: usize,
}

impl UnbondingReport {
    /// Vrai si aucun événement n'a été libéré.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.released.is_empty()
    }
}

/// Libère tous les unbondings mûrs.
///
/// ## Comportement
///
/// Pour chaque `PendingUnbonding` avec `mature_at <= ctx.current_time` :
///
/// 1. Crédite `delegator` du montant.
/// 2. Décrémente `Delegation(delegator, validator).unbonding`.
/// 3. Si `Delegation` devient vide, supprime l'entrée.
/// 4. Supprime l'événement d'unbonding.
///
/// ## Déterminisme
///
/// `ctx.current_time` provient du header du bloc courant, donc identique
/// sur tous les nœuds. La fonction est **idempotente** : un second appel
/// avec le même `ctx` ne libère rien de plus (les entrées ont été
/// supprimées).
pub fn process_matured_unbondings(
    state: &mut NativeState,
    ctx: &ExecutionContext,
) -> Result<UnbondingReport, ApplyError> {
    let now = ctx.current_time;
    let mut report = UnbondingReport::default();

    // `iter_pending_unbondings` renvoie déjà trié par id.
    let pending = state.iter_pending_unbondings();

    for p in pending {
        if !p.is_mature(now) {
            report.still_pending += 1;
            continue;
        }

        // 1. Créditer le compte.
        state
            .credit(p.delegator, p.amount)
            .map_err(ApplyError::State)?;

        // 2. Décrémenter l'agrégat `Delegation.unbonding`.
        if let Some(mut d) = state.get_delegation(&p.delegator, &p.validator) {
            d.unbonding = d.unbonding.checked_sub(p.amount).unwrap_or(Amount::ZERO);
            if d.unbonding.is_zero() {
                d.unbonding_until = None;
            }
            if d.is_empty() {
                state.remove_delegation(&p.delegator, &p.validator);
            } else {
                state.set_delegation(d);
            }
        }

        // 3. Supprimer l'événement.
        state.remove_pending_unbonding(p.id);

        report.released.push(ReleasedUnbonding {
            id: p.id,
            delegator: p.delegator,
            validator: p.validator,
            amount: p.amount,
        });
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sango_crypto::{derive_native_address, NativeKeypair};
    use sango_primitives::ChainId32;
    use sango_types::{staking_params, Delegation, PendingUnbonding, ValidatorInfo};

    fn chain() -> ChainId32 {
        ChainId32::from_bytes([0x11; 32])
    }

    fn ctx_at(now: u64) -> ExecutionContext {
        ExecutionContext {
            chain_id: chain(),
            base_fee: 10,
            fee_recipient: NativeAddress::from_bytes([0xef; 20]),
            initial_supply: Amount::from_sango(1_000_000_000).unwrap(),
            current_time: now,
            current_height: 1,
            rewards_enabled: false,
            downtime_enabled: false,
        }
    }

    /// Prépare un state avec un validateur enregistré et un unbonding
    /// en attente.
    fn setup_with_unbonding(mature_at: u64) -> (NativeState, NativeAddress, NativeAddress, u64) {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let delegator = derive_native_address(&kp.public_key());
        let validator = delegator; // self-stake

        let mut state = NativeState::new();
        state.set_validator(ValidatorInfo {
            address: validator,
            public_key: kp.public_key(),
            self_stake: Amount::from_sango(100_000).unwrap(),
            total_delegated: Amount::ZERO,
            commission_bps: 700,
            pending_commission_bps: None,
            pending_commission_at: None,
            jailed: false,
            jailed_until: None,
            downtime_window_start: 0,
            downtime_missed: 0,
        });

        // Simuler un unbond : écrire dans le Delegation agrégat + PendingUnbonding.
        let amount = Amount::from_sango(50_000).unwrap();
        let mut d = Delegation::empty(delegator, validator);
        d.unbonding = amount;
        d.unbonding_until = Some(mature_at);
        state.set_delegation(d);

        let id = state.alloc_unbonding_id().unwrap();
        state.put_pending_unbonding(PendingUnbonding {
            id,
            delegator,
            validator,
            amount,
            mature_at,
        });

        (state, delegator, validator, id)
    }

    #[test]
    fn no_pending_returns_empty_report() {
        let mut state = NativeState::new();
        let r = process_matured_unbondings(&mut state, &ctx_at(1_700_000_000)).unwrap();
        assert!(r.is_empty());
        assert_eq!(r.still_pending, 0);
    }

    #[test]
    fn not_yet_mature_is_not_released() {
        let mature_at = 1_800_000_000;
        let (mut state, delegator, _, _) = setup_with_unbonding(mature_at);
        let before = state.balance_of(&delegator);

        let r = process_matured_unbondings(&mut state, &ctx_at(mature_at - 1)).unwrap();
        assert!(r.is_empty());
        assert_eq!(r.still_pending, 1);
        assert_eq!(state.balance_of(&delegator), before);
    }

    #[test]
    fn mature_is_released_and_credited() {
        let mature_at = 1_800_000_000;
        let (mut state, delegator, validator, id) = setup_with_unbonding(mature_at);
        let before = state.balance_of(&delegator);

        let r = process_matured_unbondings(&mut state, &ctx_at(mature_at)).unwrap();
        assert_eq!(r.released.len(), 1);
        assert_eq!(r.released[0].id, id);
        assert_eq!(r.released[0].delegator, delegator);
        assert_eq!(r.released[0].validator, validator);
        assert_eq!(r.released[0].amount, Amount::from_sango(50_000).unwrap());

        // Compte crédité.
        assert_eq!(
            state.balance_of(&delegator),
            before
                .checked_add(Amount::from_sango(50_000).unwrap())
                .unwrap()
        );

        // Événement supprimé.
        assert!(state.get_pending_unbonding(id).is_none());
        assert!(state.iter_pending_unbondings().is_empty());

        // Délégation supprimée (bonded = 0, unbonding = 0, rewards = 0).
        assert!(state.get_delegation(&delegator, &validator).is_none());
    }

    #[test]
    fn release_exactly_at_mature_at() {
        let mature_at = 1_800_000_000;
        let (mut state, _, _, _) = setup_with_unbonding(mature_at);
        let r = process_matured_unbondings(&mut state, &ctx_at(mature_at)).unwrap();
        assert_eq!(r.released.len(), 1);
    }

    #[test]
    fn idempotent_when_called_twice() {
        let mature_at = 1_800_000_000;
        let (mut state, delegator, _, _) = setup_with_unbonding(mature_at);
        let r1 = process_matured_unbondings(&mut state, &ctx_at(mature_at)).unwrap();
        assert_eq!(r1.released.len(), 1);

        let root_after_first = state.native_state_root();
        let r2 = process_matured_unbondings(&mut state, &ctx_at(mature_at + 1000)).unwrap();
        assert!(r2.is_empty(), "second call should release nothing");
        assert_eq!(state.native_state_root(), root_after_first);
        let _ = delegator;
    }

    #[test]
    fn multiple_events_released_in_order() {
        let t0 = 1_700_000_000;
        let period = staking_params::UNBONDING_PERIOD_SECS;

        let kp = NativeKeypair::from_seed([0x42; 32]);
        let addr = derive_native_address(&kp.public_key());
        let mut state = NativeState::new();
        state.set_validator(ValidatorInfo {
            address: addr,
            public_key: kp.public_key(),
            self_stake: Amount::from_sango(200_000).unwrap(),
            total_delegated: Amount::ZERO,
            commission_bps: 700,
            pending_commission_bps: None,
            pending_commission_at: None,
            jailed: false,
            jailed_until: None,
            downtime_window_start: 0,
            downtime_missed: 0,
        });

        // 3 unbonds à t0, t0+1s, t0+2s → maturités décalées.
        for i in 0..3u64 {
            let amount = Amount::from_sango(1_000).unwrap();
            let mut d = state
                .get_delegation(&addr, &addr)
                .unwrap_or_else(|| Delegation::empty(addr, addr));
            d.unbonding = d.unbonding.checked_add(amount).unwrap();
            d.unbonding_until = Some(t0 + i + period);
            state.set_delegation(d);

            let id = state.alloc_unbonding_id().unwrap();
            state.put_pending_unbonding(PendingUnbonding {
                id,
                delegator: addr,
                validator: addr,
                amount,
                mature_at: t0 + i + period,
            });
        }

        // Avance à t0 + period → seul le 1er doit être libéré.
        let r = process_matured_unbondings(&mut state, &ctx_at(t0 + period)).unwrap();
        assert_eq!(r.released.len(), 1);
        assert_eq!(r.released[0].id, 0);
        assert_eq!(r.still_pending, 2);

        // Avance à t0 + 2 + period → les 3 sont libérés.
        let r = process_matured_unbondings(&mut state, &ctx_at(t0 + 2 + period)).unwrap();
        assert_eq!(r.released.len(), 2);
        assert_eq!(r.still_pending, 0);
    }

    #[test]
    fn releases_partially_keeping_delegation_if_bonded() {
        use sango_types::Delegation;
        let mature_at = 1_800_000_000;
        let validator_kp = NativeKeypair::from_seed([0x42; 32]);
        let delegator_kp = NativeKeypair::from_seed([0x01; 32]);
        let validator = derive_native_address(&validator_kp.public_key());
        let delegator = derive_native_address(&delegator_kp.public_key());

        let mut state = NativeState::new();
        state.set_validator(ValidatorInfo {
            address: validator,
            public_key: validator_kp.public_key(),
            self_stake: Amount::from_sango(100_000).unwrap(),
            total_delegated: Amount::from_sango(10_000).unwrap(),
            commission_bps: 700,
            pending_commission_bps: None,
            pending_commission_at: None,
            jailed: false,
            jailed_until: None,
            downtime_window_start: 0,
            downtime_missed: 0,
        });

        // Delegation avec bonded=5000 et unbonding=1000.
        let mut d = Delegation::empty(delegator, validator);
        d.bonded = Amount::from_sango(5_000).unwrap();
        d.unbonding = Amount::from_sango(1_000).unwrap();
        d.unbonding_until = Some(mature_at);
        state.set_delegation(d);

        let id = state.alloc_unbonding_id().unwrap();
        state.put_pending_unbonding(PendingUnbonding {
            id,
            delegator,
            validator,
            amount: Amount::from_sango(1_000).unwrap(),
            mature_at,
        });

        process_matured_unbondings(&mut state, &ctx_at(mature_at)).unwrap();

        // Délégation conservée (bonded > 0) avec unbonding=0.
        let d = state.get_delegation(&delegator, &validator).unwrap();
        assert_eq!(d.bonded, Amount::from_sango(5_000).unwrap());
        assert_eq!(d.unbonding, Amount::ZERO);
        assert!(d.unbonding_until.is_none());
    }
}
