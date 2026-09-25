//! Suivi de la participation des validateurs (downtime).
//!
//! Freeze section 47 : un validateur qui participe à moins de 80 % des
//! blocs sur une fenêtre de 100 blocs est jailé (pas de slash financier).
//!
//! ## Fenêtre glissante
//!
//! Chaque validateur maintient :
//!
//! - `downtime_window_start` : hauteur du début de la fenêtre courante ;
//! - `downtime_missed` : nombre de blocs manqués dans cette fenêtre.
//!
//! À chaque bloc, on incrémente `downtime_missed` si le validateur n'a pas
//! participé (absence de precommit dans le certificat de commit). Quand
//! `height - window_start >= 100`, on évalue la fenêtre :
//!
//! - si `missed > 20` → jail 5 000 blocs ;
//! - dans tous les cas, on démarre une nouvelle fenêtre.

use sango_primitives::NativeAddress;
use sango_state::NativeState;
use sango_types::staking_params;

use crate::error::ApplyError;
use crate::ExecutionContext;

/// Taille de la fenêtre d'observation (blocs).
pub const DOWNTIME_WINDOW: u64 = 100;

/// Nombre maximal de blocs manqués autorisés sur la fenêtre.
///
/// `100 * (1 - 0.80) = 20`.
pub const MAX_MISSED: u32 = 20;

/// Résultat d'un enregistrement de participation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ParticipationReport {
    /// Validateurs qui ont été jailés lors de cet enregistrement.
    pub newly_jailed: Vec<NativeAddress>,
    /// Validateurs dont la fenêtre a été évaluée (et réinitialisée).
    pub windows_evaluated: usize,
}

/// Enregistre la participation pour un bloc.
///
/// ## Paramètres
///
/// - `active_validators` : tous les validateurs actuellement dans l'ensemble
///   actif (typiquement ceux dont le `jailed == false`).
/// - `participants` : sous-ensemble qui a signé un precommit pour le bloc
///   qui vient d'être appliqué.
/// - `ctx.current_height` : hauteur du bloc appliqué.
///
/// ## Comportement
///
/// Pour chaque validateur actif :
///
/// 1. Incrémente `downtime_missed` si absent des `participants`.
/// 2. Si la fenêtre courante est terminée (`height - start >= 100`),
///    évalue et reset :
///    - `missed > 20` → jail (5 000 blocs) ;
///    - fenêtre suivante démarre à `height + 1`.
///
/// # Erreurs
///
/// Retourne une erreur d'état si l'écriture échoue.
pub fn record_participation(
    state: &mut NativeState,
    active_validators: &[NativeAddress],
    participants: &[NativeAddress],
    ctx: &ExecutionContext,
) -> Result<ParticipationReport, ApplyError> {
    let height = ctx.current_height;
    let mut report = ParticipationReport::default();

    for validator in active_validators {
        let Some(mut info) = state.get_validator(validator) else {
            continue;
        };
        let original_window_start = info.downtime_window_start;
        let original_missed = info.downtime_missed;
        let original_jailed = info.jailed;

        // 1. Initialisation au premier bloc du validateur.
        if info.downtime_window_start == 0 && info.downtime_missed == 0 && height > 0 {
            // Premier enregistrement pour ce validateur : démarrer la
            // fenêtre à `height`.
            info.downtime_window_start = height;
        }

        // 2. Incrément.
        if !participants.contains(validator) {
            info.downtime_missed = info.downtime_missed.saturating_add(1);
        }

        // 3. Évaluation de la fenêtre.
        let window_end = info.downtime_window_start.saturating_add(DOWNTIME_WINDOW);
        if height.saturating_add(1) >= window_end {
            report.windows_evaluated += 1;

            // Décision de jail avant reset.
            if !info.jailed && info.downtime_missed > MAX_MISSED {
                let jail_until = ctx.current_time.saturating_add(
                    staking_params::DOWNTIME_JAIL_BLOCKS * 5, // 5s par bloc
                );
                info.jailed = true;
                info.jailed_until = Some(jail_until);
                report.newly_jailed.push(*validator);
            }

            // Reset de la fenêtre.
            info.downtime_window_start = height.saturating_add(1);
            info.downtime_missed = 0;
        }

        // Éviter les écritures inutiles : ne pas réécrire le validateur si
        // rien n'a changé (ni fenêtre, ni compteur, ni jail).
        if info.downtime_window_start != original_window_start
            || info.downtime_missed != original_missed
            || info.jailed != original_jailed
        {
            state.set_validator(info);
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sango_crypto::{derive_native_address, NativeKeypair};
    use sango_primitives::{Amount, ChainId32, PublicKey};
    use sango_types::ValidatorInfo;

    fn chain() -> ChainId32 {
        ChainId32::from_bytes([0x11; 32])
    }

    fn ctx(height: u64) -> ExecutionContext {
        ExecutionContext {
            chain_id: chain(),
            base_fee: 10,
            fee_recipient: NativeAddress::from_bytes([0xef; 20]),
            initial_supply: Amount::from_sango(1_000_000_000).unwrap(),
            current_time: 1_700_000_000 + height * 5,
            current_height: height,
            evm_chain_id: crate::DEFAULT_EVM_CHAIN_ID,
            rewards_enabled: false,
            downtime_enabled: false,
        }
    }

    fn make_validator(addr: NativeAddress) -> ValidatorInfo {
        ValidatorInfo {
            address: addr,
            public_key: PublicKey::from_bytes([0x01; 32]),
            self_stake: Amount::from_sango(100_000).unwrap(),
            total_delegated: Amount::ZERO,
            commission_bps: 700,
            pending_commission_bps: None,
            pending_commission_at: None,
            jailed: false,
            jailed_until: None,
            downtime_window_start: 0,
            downtime_missed: 0,
        }
    }

    #[test]
    fn full_participation_does_not_jail() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let addr = derive_native_address(&kp.public_key());
        let mut state = NativeState::new();
        state.set_validator(make_validator(addr));

        let active = vec![addr];
        for h in 0..150 {
            let participants = vec![addr];
            let report = record_participation(&mut state, &active, &participants, &ctx(h)).unwrap();
            assert!(report.newly_jailed.is_empty());
        }

        let info = state.get_validator(&addr).unwrap();
        assert!(!info.jailed);
        assert_eq!(info.downtime_missed, 0);
    }

    #[test]
    fn below_threshold_jails() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let addr = derive_native_address(&kp.public_key());
        let mut state = NativeState::new();
        state.set_validator(make_validator(addr));

        let active = vec![addr];
        // 30 blocs sur 100 sans participation → missed = 30 > 20.
        for h in 0..100 {
            let participants: Vec<NativeAddress> = if h < 30 { vec![] } else { vec![addr] };
            let report = record_participation(&mut state, &active, &participants, &ctx(h)).unwrap();
            if h == 99 {
                assert_eq!(report.newly_jailed, vec![addr]);
            }
        }

        let info = state.get_validator(&addr).unwrap();
        assert!(info.jailed);
        assert!(info.jailed_until.is_some());
        assert_eq!(info.downtime_missed, 0); // reset après évaluation
    }

    #[test]
    fn exactly_at_threshold_does_not_jail() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let addr = derive_native_address(&kp.public_key());
        let mut state = NativeState::new();
        state.set_validator(make_validator(addr));

        let active = vec![addr];
        // Exactement 20 blocs manqués → PAS de jail.
        for h in 0..100 {
            let participants: Vec<NativeAddress> = if h < 20 { vec![] } else { vec![addr] };
            let report = record_participation(&mut state, &active, &participants, &ctx(h)).unwrap();
            if h == 99 {
                assert!(
                    report.newly_jailed.is_empty(),
                    "seuil atteint mais pas dépassé"
                );
            }
        }

        let info = state.get_validator(&addr).unwrap();
        assert!(!info.jailed);
    }

    #[test]
    fn already_jailed_not_rejailed() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let addr = derive_native_address(&kp.public_key());
        let mut state = NativeState::new();
        let mut info = make_validator(addr);
        info.jailed = true;
        info.jailed_until = Some(1_900_000_000);
        state.set_validator(info);

        let active = vec![addr];
        for h in 0..150 {
            let participants: Vec<NativeAddress> = vec![];
            let report = record_participation(&mut state, &active, &participants, &ctx(h)).unwrap();
            assert!(
                report.newly_jailed.is_empty(),
                "un validateur déjà jailé ne doit pas être re-jailé"
            );
        }
    }

    #[test]
    fn multiple_validators_independent() {
        let kp1 = NativeKeypair::from_seed([0x01; 32]);
        let kp2 = NativeKeypair::from_seed([0x02; 32]);
        let a1 = derive_native_address(&kp1.public_key());
        let a2 = derive_native_address(&kp2.public_key());

        let mut state = NativeState::new();
        state.set_validator(make_validator(a1));
        state.set_validator(make_validator(a2));

        let active = vec![a1, a2];
        // A1 participe, A2 ne participe pas.
        for h in 0..150 {
            let participants = vec![a1];
            let report = record_participation(&mut state, &active, &participants, &ctx(h)).unwrap();
            if h == 99 {
                assert_eq!(report.newly_jailed, vec![a2]);
            }
        }

        assert!(!state.get_validator(&a1).unwrap().jailed);
        assert!(state.get_validator(&a2).unwrap().jailed);
    }

    #[test]
    fn empty_active_set_returns_empty_report() {
        let mut state = NativeState::new();
        let report = record_participation(&mut state, &[], &[], &ctx(0)).unwrap();
        assert!(report.newly_jailed.is_empty());
        assert_eq!(report.windows_evaluated, 0);
    }
}
