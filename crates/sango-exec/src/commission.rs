//! Activation des commissions de validateur arrivées à échéance.
//!
//! ## Règle normative (Freeze section 50)
//!
//! Une modification de commission demandée via `TxKind::UpdateCommission`
//! prend effet après un délai de 7 jours.
//!
//! `apply_update_commission` (dans [`crate::staking`]) écrit
//! `pending_commission_bps` et `pending_commission_at`. **Ce module
//! active la bascule** dès que le délai est écoulé.
//!
//! ## Déterminisme
//!
//! Comme [`crate::unbonding::process_matured_unbondings`], cette
//! finalisation est **déterministe** : elle ne dépend que de
//! `ctx.current_time` (issu du header du bloc, identique sur tous les
//! nœuds) et de l'état. Aucun flag `_enabled` n'est nécessaire.
//!
//! ## Idempotence
//!
//! Après activation, `pending_commission_bps` et `pending_commission_at`
//! sont remis à `None` : un second appel avec le même `ctx` ne fait rien.

use sango_primitives::NativeAddress;
use sango_state::NativeState;

use crate::error::ApplyError;
use crate::ExecutionContext;

/// Détail d'une commission activée.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActivatedCommission {
    /// Adresse native du validateur.
    pub validator: NativeAddress,
    /// Ancienne commission (bps) — celle qui était active.
    pub old_bps: u32,
    /// Nouvelle commission (bps) désormais active.
    pub new_bps: u32,
}

/// Rapport d'un passage d'activation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CommissionReport {
    /// Commissions activées lors de cet appel.
    pub activated: Vec<ActivatedCommission>,
    /// Nombre de validateurs dont la commission reste en attente
    /// (`pending_commission_at > ctx.current_time`).
    pub still_pending: usize,
}

impl CommissionReport {
    /// Vrai si aucune commission n'a été activée.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.activated.is_empty()
    }
}

/// Active toutes les commissions dont le délai de 7 jours est écoulé.
///
/// ## Comportement
///
/// Pour chaque validateur avec `pending_commission_bps.is_some()` et
/// `pending_commission_at.is_some()` :
///
/// - si `pending_commission_at <= ctx.current_time` :
///   - `commission_bps = pending_commission_bps`
///   - `pending_commission_bps = None`
///   - `pending_commission_at = None`
///   - `state.set_validator(info)`
/// - sinon : compté dans `still_pending`.
///
/// ## Déterminisme
///
/// Dépend uniquement de `ctx.current_time` (header du bloc) et de
/// l'état. Ordre d'itération stable (via `state.all_validators()`,
/// trié par adresse).
pub fn process_pending_commissions(
    state: &mut NativeState,
    ctx: &ExecutionContext,
) -> Result<CommissionReport, ApplyError> {
    let now = ctx.current_time;
    let mut report = CommissionReport::default();

    // `all_validators` retourne une copie (clonée) : on peut donc
    // appeler `state.set_validator` dans la boucle.
    let validators = state.all_validators();
    for mut info in validators {
        let Some(new_bps) = info.pending_commission_bps else {
            continue;
        };
        let Some(at) = info.pending_commission_at else {
            // État incohérent (ne devrait jamais arriver) : on ignore.
            continue;
        };

        if at <= now {
            let old_bps = info.commission_bps;
            info.commission_bps = new_bps;
            info.pending_commission_bps = None;
            info.pending_commission_at = None;
            let addr = info.address;
            state.set_validator(info);
            report.activated.push(ActivatedCommission {
                validator: addr,
                old_bps,
                new_bps,
            });
        } else {
            report.still_pending += 1;
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sango_primitives::{Amount, ChainId32, PublicKey};
    use sango_types::ValidatorInfo;

    fn chain() -> ChainId32 {
        ChainId32::from_bytes([0x11; 32])
    }

    fn now() -> u64 {
        1_700_000_000
    }

    fn ctx_at(t: u64) -> ExecutionContext {
        ExecutionContext {
            chain_id: chain(),
            base_fee: 10,
            fee_recipient: NativeAddress::from_bytes([0xef; 20]),
            initial_supply: Amount::from_sango(1_000_000_000).unwrap(),
            current_time: t,
            current_height: 1,
            rewards_enabled: false,
            downtime_enabled: false,
            evm_chain_id: crate::DEFAULT_EVM_CHAIN_ID,
        }
    }

    fn mk_validator(
        addr: NativeAddress,
        current_bps: u32,
        pending: Option<(u32, u64)>,
    ) -> ValidatorInfo {
        let (pending_bps, pending_at) = match pending {
            Some((bps, at)) => (Some(bps), Some(at)),
            None => (None, None),
        };
        ValidatorInfo {
            address: addr,
            public_key: PublicKey::from_bytes([0x01; 32]),
            self_stake: Amount::from_sango(100_000).unwrap(),
            total_delegated: Amount::ZERO,
            commission_bps: current_bps,
            pending_commission_bps: pending_bps,
            pending_commission_at: pending_at,
            jailed: false,
            jailed_until: None,
            downtime_window_start: 0,
            downtime_missed: 0,
        }
    }

    // --- Cas vides --------------------------------------------------------

    #[test]
    fn empty_state_returns_empty_report() {
        let mut state = NativeState::new();
        let r = process_pending_commissions(&mut state, &ctx_at(now())).unwrap();
        assert!(r.is_empty());
        assert_eq!(r.still_pending, 0);
    }

    #[test]
    fn validator_without_pending_is_skipped() {
        let addr = NativeAddress::from_bytes([0xaa; 20]);
        let mut state = NativeState::new();
        state.set_validator(mk_validator(addr, 700, None));

        let r = process_pending_commissions(&mut state, &ctx_at(now())).unwrap();
        assert!(r.is_empty());
        assert_eq!(r.still_pending, 0);

        let info = state.get_validator(&addr).unwrap();
        assert_eq!(info.commission_bps, 700);
    }

    // --- Timing -----------------------------------------------------------

    #[test]
    fn does_not_activate_before_time() {
        let addr = NativeAddress::from_bytes([0xaa; 20]);
        let future = now() + 1000;
        let mut state = NativeState::new();
        state.set_validator(mk_validator(addr, 700, Some((900, future))));

        let r = process_pending_commissions(&mut state, &ctx_at(now())).unwrap();
        assert!(r.is_empty());
        assert_eq!(r.still_pending, 1);

        let info = state.get_validator(&addr).unwrap();
        assert_eq!(info.commission_bps, 700);
        assert_eq!(info.pending_commission_bps, Some(900));
        assert_eq!(info.pending_commission_at, Some(future));
    }

    #[test]
    fn activates_exactly_at_time() {
        let addr = NativeAddress::from_bytes([0xaa; 20]);
        let mut state = NativeState::new();
        state.set_validator(mk_validator(addr, 700, Some((900, now()))));

        let r = process_pending_commissions(&mut state, &ctx_at(now())).unwrap();
        assert_eq!(r.activated.len(), 1);
        assert_eq!(
            r.activated[0],
            ActivatedCommission {
                validator: addr,
                old_bps: 700,
                new_bps: 900,
            }
        );
        assert_eq!(r.still_pending, 0);

        let info = state.get_validator(&addr).unwrap();
        assert_eq!(info.commission_bps, 900);
        assert!(info.pending_commission_bps.is_none());
        assert!(info.pending_commission_at.is_none());
    }

    #[test]
    fn activates_after_time() {
        let addr = NativeAddress::from_bytes([0xaa; 20]);
        let mut state = NativeState::new();
        state.set_validator(mk_validator(addr, 700, Some((900, now()))));

        let r = process_pending_commissions(&mut state, &ctx_at(now() + 1)).unwrap();
        assert_eq!(r.activated.len(), 1);
        assert_eq!(state.get_validator(&addr).unwrap().commission_bps, 900);
    }

    // --- Idempotence ------------------------------------------------------

    #[test]
    fn idempotent_when_called_twice() {
        let addr = NativeAddress::from_bytes([0xaa; 20]);
        let mut state = NativeState::new();
        state.set_validator(mk_validator(addr, 700, Some((900, now()))));

        let r1 = process_pending_commissions(&mut state, &ctx_at(now())).unwrap();
        assert_eq!(r1.activated.len(), 1);

        let root_after = state.native_state_root();

        let r2 = process_pending_commissions(&mut state, &ctx_at(now() + 100)).unwrap();
        assert!(r2.is_empty());
        assert_eq!(r2.still_pending, 0);
        assert_eq!(state.native_state_root(), root_after);
    }

    // --- Multi-validateurs ------------------------------------------------

    #[test]
    fn multiple_validators_independent() {
        let a = NativeAddress::from_bytes([0x01; 20]);
        let b = NativeAddress::from_bytes([0x02; 20]);
        let c = NativeAddress::from_bytes([0x03; 20]);

        let mut state = NativeState::new();
        state.set_validator(mk_validator(a, 700, Some((800, now())))); // dû
        state.set_validator(mk_validator(b, 500, Some((600, now() + 1000)))); // futur
        state.set_validator(mk_validator(c, 300, Some((400, now() - 100)))); // dû avant

        let r = process_pending_commissions(&mut state, &ctx_at(now())).unwrap();
        assert_eq!(r.activated.len(), 2);
        assert_eq!(r.still_pending, 1);

        assert_eq!(state.get_validator(&a).unwrap().commission_bps, 800);
        assert_eq!(state.get_validator(&b).unwrap().commission_bps, 500); // inchangé
        assert_eq!(state.get_validator(&c).unwrap().commission_bps, 400);
    }

    // --- Intégrité des autres champs --------------------------------------

    #[test]
    fn preserves_other_fields() {
        let addr = NativeAddress::from_bytes([0xaa; 20]);
        let mut state = NativeState::new();
        let mut info = mk_validator(addr, 700, Some((900, now())));
        info.total_delegated = Amount::from_sango(50_000).unwrap();
        info.jailed = true;
        info.jailed_until = Some(now() + 5000);
        info.downtime_missed = 7;
        info.downtime_window_start = 100;
        state.set_validator(info);

        process_pending_commissions(&mut state, &ctx_at(now())).unwrap();

        let after = state.get_validator(&addr).unwrap();
        assert_eq!(after.commission_bps, 900);
        assert_eq!(after.total_delegated, Amount::from_sango(50_000).unwrap());
        assert!(after.jailed);
        assert_eq!(after.jailed_until, Some(now() + 5000));
        assert_eq!(after.downtime_missed, 7);
        assert_eq!(after.downtime_window_start, 100);
    }

    // --- Déterminisme -----------------------------------------------------

    #[test]
    fn deterministic_with_same_ctx() {
        let addr = NativeAddress::from_bytes([0xaa; 20]);
        let mk_state = || {
            let mut s = NativeState::new();
            s.set_validator(mk_validator(addr, 700, Some((900, now()))));
            s
        };
        let mut a = mk_state();
        let mut b = mk_state();
        let ra = process_pending_commissions(&mut a, &ctx_at(now())).unwrap();
        let rb = process_pending_commissions(&mut b, &ctx_at(now())).unwrap();
        assert_eq!(ra, rb);
        assert_eq!(a.native_state_root(), b.native_state_root());
    }
}
