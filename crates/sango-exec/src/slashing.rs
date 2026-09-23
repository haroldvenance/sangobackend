//! Slashing : application d'une evidence (double-sign) et jail.
//!
//! Freeze section 46.

use sango_primitives::{Amount, NativeAddress};
use sango_state::NativeState;
use sango_types::{staking_params, Evidence, EvidenceRecord};

use crate::error::ApplyError;
use crate::ExecutionContext;

/// Durée de jail après un double-sign (21 jours).
pub const DOUBLE_SIGN_JAIL_SECS: u64 = 21 * 24 * 3600;

/// Résultat de l'application d'une evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceApplied {
    /// Identifiant de l'evidence.
    pub evidence_id: sango_primitives::Hash32,
    /// Validateur fautif.
    pub validator: NativeAddress,
    /// Montant total slashé (self + délégué).
    pub slashed_total: Amount,
    /// Montant slashé sur le self-stake.
    pub slashed_self: Amount,
    /// Montant slashé sur les délégations.
    pub slashed_delegated: Amount,
    /// Timestamp Unix de fin de jail.
    pub jailed_until: u64,
}

/// Applique une evidence : slash 5 %, burn 100 %, jail 21 jours.
///
/// ## Comportement (Freeze section 46)
///
/// - Vérifie que l'evidence n'a pas déjà été appliquée.
/// - Slash 5 % du self-stake et de chaque délégation vers le validateur.
/// - Met à jour `total_delegated` du validateur.
/// - Met le validateur en jail pour 21 jours.
/// - Enregistre l'evidence dans le namespace `Evidence` pour empêcher
///   un double slash.
///
/// # Erreurs
///
/// - [`ApplyError::EvidenceAlreadyApplied`] si déjà appliquée.
/// - [`ApplyError::ValidatorNotFound`] si le validateur n'existe pas.
pub fn apply_evidence(
    state: &mut NativeState,
    evidence: &Evidence,
    ctx: &ExecutionContext,
) -> Result<EvidenceApplied, ApplyError> {
    let evidence_id = evidence.evidence_id();

    // (1) Anti-double-slash.
    if state.has_evidence(&evidence_id) {
        return Err(ApplyError::EvidenceAlreadyApplied(evidence_id));
    }

    // (2) Validateur.
    let validator_address = evidence.validator_address;
    let mut info = state
        .get_validator(&validator_address)
        .ok_or(ApplyError::ValidatorNotFound(validator_address))?;

    let slash_bps = staking_params::DOUBLE_SIGN_SLASH_BPS as u128;

    // (3) Slash self-stake.
    let self_before = info.self_stake.base_units();
    let self_slash = self_before.saturating_mul(slash_bps) / 10_000;
    let self_after = self_before - self_slash;

    // (4) Slash chaque délégation.
    let mut total_delegator_slashed: u128 = 0;
    let delegations = state.delegations_for(&validator_address);
    for mut d in delegations {
        let before = d.bonded.base_units();
        let slash = before.saturating_mul(slash_bps) / 10_000;
        d.bonded = Amount::from_base_units(before - slash);
        state.set_delegation(d);
        total_delegator_slashed += slash;
    }

    // (5) Mettre à jour le validateur.
    info.self_stake = Amount::from_base_units(self_after);
    let delegated_before = info.total_delegated.base_units();
    info.total_delegated = Amount::from_base_units(delegated_before - total_delegator_slashed);
    info.jailed = true;
    info.jailed_until = Some(ctx.current_time.saturating_add(DOUBLE_SIGN_JAIL_SECS));
    state.set_validator(info);

    // (6) Burn le total slashé (100 %).
    let slashed_total = self_slash + total_delegator_slashed;
    state
        .add_burned(Amount::from_base_units(slashed_total))
        .map_err(ApplyError::State)?;

    // (7) Marquer l'evidence.
    state.set_evidence(EvidenceRecord {
        evidence_id,
        validator_address,
        applied_at_height: ctx.current_height,
        slashed: Amount::from_base_units(slashed_total),
    });

    Ok(EvidenceApplied {
        evidence_id,
        validator: validator_address,
        slashed_total: Amount::from_base_units(slashed_total),
        slashed_self: Amount::from_base_units(self_slash),
        slashed_delegated: Amount::from_base_units(total_delegator_slashed),
        jailed_until: ctx.current_time.saturating_add(DOUBLE_SIGN_JAIL_SECS),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sango_crypto::{derive_native_address, NativeKeypair};
    use sango_primitives::{ChainId32, PublicKey, Signature};
    use sango_types::{
        ConsensusMessage, ConsensusMessageType, Delegation, EvidenceType, ValidatorInfo,
    };

    fn chain() -> ChainId32 {
        ChainId32::from_bytes([0x11; 32])
    }

    fn now() -> u64 {
        1_700_000_000
    }

    fn ctx() -> ExecutionContext {
        ExecutionContext {
            chain_id: chain(),
            base_fee: 10,
            fee_recipient: NativeAddress::from_bytes([0xef; 20]),
            initial_supply: Amount::from_sango(1_000_000_000).unwrap(),
            current_time: now(),
            current_height: 1,
        }
    }

    fn validator_info(addr: NativeAddress, pk: PublicKey, self_stake: u128) -> ValidatorInfo {
        ValidatorInfo {
            address: addr,
            public_key: pk,
            self_stake: Amount::from_sango(self_stake).unwrap(),
            total_delegated: Amount::ZERO,
            commission_bps: 700,
            pending_commission_bps: None,
            pending_commission_at: None,
            jailed: false,
            jailed_until: None,
        }
    }

    fn make_evidence(validator: NativeAddress) -> Evidence {
        Evidence {
            version: 1,
            evidence_type: EvidenceType::DoublePrevote,
            chain_id: chain(),
            epoch: sango_primitives::Epoch::new(0),
            height: sango_primitives::Height::new(100),
            round: sango_primitives::Round::new(0),
            validator_address: validator,
            message_1: ConsensusMessage {
                message_type: ConsensusMessageType::Prevote,
                canonical_payload: vec![1, 2, 3],
                signature: Signature::ZERO,
            },
            message_2: ConsensusMessage {
                message_type: ConsensusMessageType::Prevote,
                canonical_payload: vec![4, 5, 6],
                signature: Signature::ZERO,
            },
        }
    }

    #[test]
    fn slash_5_percent_of_self_stake() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let addr = derive_native_address(&kp.public_key());
        let mut state = NativeState::new();
        state.set_validator(validator_info(addr, kp.public_key(), 100_000));

        let ev = make_evidence(addr);
        let r = apply_evidence(&mut state, &ev, &ctx()).unwrap();

        // 5 % de 100_000 SANGO = 5_000 SANGO.
        let expected_slash = Amount::from_sango(5_000).unwrap();
        assert_eq!(r.slashed_self, expected_slash);
        assert_eq!(r.slashed_delegated, Amount::ZERO);
        assert_eq!(r.slashed_total, expected_slash);

        let info = state.get_validator(&addr).unwrap();
        assert_eq!(info.self_stake, Amount::from_sango(95_000).unwrap());
        assert!(info.jailed);
        assert_eq!(info.jailed_until, Some(now() + DOUBLE_SIGN_JAIL_SECS));
        assert_eq!(state.total_burned(), expected_slash);
    }

    #[test]
    fn slash_also_reduces_delegations() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let addr = derive_native_address(&kp.public_key());
        let mut state = NativeState::new();

        let mut info = validator_info(addr, kp.public_key(), 100_000);
        info.total_delegated = Amount::from_sango(50_000).unwrap();
        state.set_validator(info);

        // Deux délégations : 30k + 20k.
        let mut d1 = Delegation::empty(NativeAddress::from_bytes([0x01; 20]), addr);
        d1.bonded = Amount::from_sango(30_000).unwrap();
        state.set_delegation(d1);

        let mut d2 = Delegation::empty(NativeAddress::from_bytes([0x02; 20]), addr);
        d2.bonded = Amount::from_sango(20_000).unwrap();
        state.set_delegation(d2);

        let ev = make_evidence(addr);
        let r = apply_evidence(&mut state, &ev, &ctx()).unwrap();

        // 5 % self = 5 000 SANGO ; 5 % des délégations = 1 500 + 1 000 = 2 500 SANGO
        assert_eq!(r.slashed_self, Amount::from_sango(5_000).unwrap());
        assert_eq!(r.slashed_delegated, Amount::from_sango(2_500).unwrap());

        let d1_after = state
            .get_delegation(&NativeAddress::from_bytes([0x01; 20]), &addr)
            .unwrap();
        assert_eq!(d1_after.bonded, Amount::from_sango(28_500).unwrap());

        let d2_after = state
            .get_delegation(&NativeAddress::from_bytes([0x02; 20]), &addr)
            .unwrap();
        assert_eq!(d2_after.bonded, Amount::from_sango(19_000).unwrap());
    }

    #[test]
    fn double_application_rejected() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let addr = derive_native_address(&kp.public_key());
        let mut state = NativeState::new();
        state.set_validator(validator_info(addr, kp.public_key(), 100_000));

        let ev = make_evidence(addr);
        apply_evidence(&mut state, &ev, &ctx()).unwrap();

        let err = apply_evidence(&mut state, &ev, &ctx()).unwrap_err();
        assert!(matches!(err, ApplyError::EvidenceAlreadyApplied(_)));
    }

    #[test]
    fn unknown_validator_rejected() {
        let mut state = NativeState::new();
        let addr = NativeAddress::from_bytes([0xee; 20]);
        let ev = make_evidence(addr);
        let err = apply_evidence(&mut state, &ev, &ctx()).unwrap_err();
        assert!(matches!(err, ApplyError::ValidatorNotFound(_)));
    }

    #[test]
    fn evidence_recorded_in_state() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let addr = derive_native_address(&kp.public_key());
        let mut state = NativeState::new();
        state.set_validator(validator_info(addr, kp.public_key(), 100_000));

        let ev = make_evidence(addr);
        let evidence_id = ev.evidence_id();
        assert!(!state.has_evidence(&evidence_id));

        apply_evidence(&mut state, &ev, &ctx()).unwrap();
        assert!(state.has_evidence(&evidence_id));

        let rec = state.get_evidence(&evidence_id).unwrap();
        assert_eq!(rec.validator_address, addr);
        assert_eq!(rec.applied_at_height, 1);
    }
}
