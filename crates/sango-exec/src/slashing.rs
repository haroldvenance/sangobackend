//! Slashing : application d'une evidence (double-sign) et jail.
//!
//! Freeze section 46.
//!
//! ## Vérification
//!
//! Une `Evidence` est **vérifiée cryptographiquement** avant application :
//!
//! 1. Le validateur fautif doit exister dans l'état.
//! 2. Les deux messages doivent être du même type (`Prevote` ou
//!    `Precommit`), cohérent avec `evidence_type`.
//! 3. Les signatures Ed25519 des deux messages doivent être valides contre
//!    la clé publique enregistrée.
//! 4. Les deux messages doivent avoir `(chain_id, epoch, height, round)`
//!    identiques et égaux au contexte de l'evidence.
//! 5. Les deux messages doivent être contradictoires : `block_hash`
//!    différents.
//!
//! Sans ces contrôles, un proposant malveillant pourrait fabriquer une
//! evidence et slasher n'importe quel validateur.

use sango_codec::Decode;
use sango_crypto::{domain, verify_native};
use sango_primitives::{Amount, ChainId32, Epoch, Hash32, Height, NativeAddress, PublicKey, Round};
use sango_state::NativeState;
use sango_types::{
    staking_params, ConsensusMessage, ConsensusMessageType, Evidence, EvidenceRecord, EvidenceType,
    Precommit, Prevote,
};

use crate::error::ApplyError;
use crate::ExecutionContext;

/// Durée de jail après un double-sign (21 jours).
pub const DOUBLE_SIGN_JAIL_SECS: u64 = 21 * 24 * 3600;

/// Résultat de l'application d'une evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceApplied {
    /// Identifiant de l'evidence.
    pub evidence_id: Hash32,
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
/// ## Comportement
///
/// - **Vérifie cryptographiquement l'evidence** avant toute mutation.
/// - Refuse une evidence déjà appliquée (`has_evidence`).
/// - Slash 5 % du self-stake et de chaque délégation vers le validateur.
/// - Met le validateur en jail pour 21 jours.
/// - Enregistre l'evidence dans le namespace `Evidence`.
///
/// # Erreurs
///
/// - [`ApplyError::EvidenceAlreadyApplied`] si déjà appliquée.
/// - [`ApplyError::ValidatorNotFound`] si le validateur n'existe pas.
/// - [`ApplyError::InvalidEvidence`] si la vérification cryptographique
///   échoue.
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
    let public_key: PublicKey = info.public_key;

    // (3) Vérification cryptographique.
    verify_evidence(evidence, &public_key)?;

    let slash_bps = staking_params::DOUBLE_SIGN_SLASH_BPS as u128;

    // (4) Slash self-stake.
    let self_before = info.self_stake.base_units();
    let self_slash = self_before.saturating_mul(slash_bps) / 10_000;
    let self_after = self_before - self_slash;

    // (5) Slash chaque délégation.
    let mut total_delegator_slashed: u128 = 0;
    let delegations = state.delegations_for(&validator_address);
    for mut d in delegations {
        let before = d.bonded.base_units();
        let slash = before.saturating_mul(slash_bps) / 10_000;
        d.bonded = Amount::from_base_units(before - slash);
        state.set_delegation(d);
        total_delegator_slashed += slash;
    }

    // (6) Mettre à jour le validateur.
    info.self_stake = Amount::from_base_units(self_after);
    let delegated_before = info.total_delegated.base_units();
    info.total_delegated = Amount::from_base_units(delegated_before - total_delegator_slashed);
    info.jailed = true;
    info.jailed_until = Some(ctx.current_time.saturating_add(DOUBLE_SIGN_JAIL_SECS));
    state.set_validator(info);

    // (7) Burn le total slashé.
    let slashed_total = self_slash + total_delegator_slashed;
    state
        .add_burned(Amount::from_base_units(slashed_total))
        .map_err(ApplyError::State)?;

    // (8) Enregistrer l'evidence.
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

// --- Vérification cryptographique ------------------------------------------

/// Vérifie une evidence contre la clé publique du validateur.
fn verify_evidence(evidence: &Evidence, public_key: &PublicKey) -> Result<(), ApplyError> {
    // Type attendu et domaine.
    let (expected_type, domain_bytes) = match evidence.evidence_type {
        EvidenceType::DoublePrevote => (ConsensusMessageType::Prevote, domain::PREVOTE_V1),
        EvidenceType::DoublePrecommit => (ConsensusMessageType::Precommit, domain::PRECOMMIT_V1),
    };

    // Vérification des deux messages : type cohérent + signature valide.
    for msg in [&evidence.message_1, &evidence.message_2] {
        if msg.message_type != expected_type {
            return Err(ApplyError::InvalidEvidence(
                "message type does not match evidence type",
            ));
        }
        verify_native(
            public_key,
            domain_bytes,
            &msg.canonical_payload,
            &msg.signature,
        )
        .map_err(|_| ApplyError::InvalidEvidence("invalid signature"))?;
    }

    // Décodage pour vérification de cohérence.
    let a = decode_message(&evidence.message_1, expected_type)?;
    let b = decode_message(&evidence.message_2, expected_type)?;

    // Contexte identique et cohérent avec l'evidence.
    if a.chain_id != evidence.chain_id || b.chain_id != evidence.chain_id {
        return Err(ApplyError::InvalidEvidence("chain_id mismatch"));
    }
    if a.epoch != evidence.epoch || b.epoch != evidence.epoch {
        return Err(ApplyError::InvalidEvidence("epoch mismatch"));
    }
    if a.height != evidence.height || b.height != evidence.height {
        return Err(ApplyError::InvalidEvidence("height mismatch"));
    }
    if a.round != evidence.round || b.round != evidence.round {
        return Err(ApplyError::InvalidEvidence("round mismatch"));
    }
    if a.validator != evidence.validator_address || b.validator != evidence.validator_address {
        return Err(ApplyError::InvalidEvidence("validator mismatch"));
    }

    // Contradiction.
    if a.block_hash == b.block_hash {
        return Err(ApplyError::InvalidEvidence(
            "messages are not contradictory",
        ));
    }

    Ok(())
}

/// Champs extraits d'un message consensus après décodage.
struct DecodedMessage {
    chain_id: ChainId32,
    epoch: Epoch,
    height: Height,
    round: Round,
    block_hash: Option<Hash32>,
    validator: NativeAddress,
}

/// Décode le payload canonique d'un message consensus.
///
/// Le payload contient l'encodage **sans signature**. On reconstitue
/// l'encodage complet en concaténant la signature, puis on décode le
/// type approprié (`Prevote` ou `Precommit`).
fn decode_message(
    msg: &ConsensusMessage,
    expected: ConsensusMessageType,
) -> Result<DecodedMessage, ApplyError> {
    let mut full = msg.canonical_payload.clone();
    full.extend_from_slice(msg.signature.as_bytes());

    match expected {
        ConsensusMessageType::Prevote => {
            let p = Prevote::decode_exact(&full)
                .map_err(|_| ApplyError::InvalidEvidence("cannot decode prevote"))?;
            Ok(DecodedMessage {
                chain_id: p.chain_id,
                epoch: p.epoch,
                height: p.height,
                round: p.round,
                block_hash: p.block_hash,
                validator: p.validator_address,
            })
        }
        ConsensusMessageType::Precommit => {
            let p = Precommit::decode_exact(&full)
                .map_err(|_| ApplyError::InvalidEvidence("cannot decode precommit"))?;
            Ok(DecodedMessage {
                chain_id: p.chain_id,
                epoch: p.epoch,
                height: p.height,
                round: p.round,
                block_hash: p.block_hash,
                validator: p.validator_address,
            })
        }
    }
}

// --- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sango_crypto::{derive_native_address, NativeKeypair};
    use sango_primitives::Signature;
    use sango_types::ValidatorInfo;

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
            evm_chain_id: crate::DEFAULT_EVM_CHAIN_ID,
            rewards_enabled: false,
            downtime_enabled: false,
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
            downtime_window_start: 0,
            downtime_missed: 0,
        }
    }

    /// Construit deux prevotes contradictoires signées par `kp`.
    fn make_double_prevote(kp: &NativeKeypair) -> Evidence {
        let pk = kp.public_key();
        let addr = derive_native_address(&pk);
        let base = Prevote {
            chain_id: chain(),
            epoch: Epoch::new(0),
            height: Height::new(100),
            round: Round::new(0),
            block_hash: Some(Hash32::from_bytes([0x01; 32])),
            validator_address: addr,
            validator_signature: Signature::ZERO,
        }
        .sign(kp);
        let second = Prevote {
            block_hash: Some(Hash32::from_bytes([0x02; 32])),
            validator_signature: Signature::ZERO,
            ..base
        }
        .sign(kp);

        Evidence {
            version: sango_types::PROTOCOL_VERSION_V1,
            evidence_type: EvidenceType::DoublePrevote,
            chain_id: chain(),
            epoch: Epoch::new(0),
            height: Height::new(100),
            round: Round::new(0),
            validator_address: addr,
            message_1: ConsensusMessage {
                message_type: ConsensusMessageType::Prevote,
                canonical_payload: base.encode_unsigned_to_vec(),
                signature: base.validator_signature,
            },
            message_2: ConsensusMessage {
                message_type: ConsensusMessageType::Prevote,
                canonical_payload: second.encode_unsigned_to_vec(),
                signature: second.validator_signature,
            },
        }
    }

    fn make_double_precommit(kp: &NativeKeypair) -> Evidence {
        let pk = kp.public_key();
        let addr = derive_native_address(&pk);
        let base = Precommit {
            chain_id: chain(),
            epoch: Epoch::new(0),
            height: Height::new(100),
            round: Round::new(0),
            block_hash: Some(Hash32::from_bytes([0x01; 32])),
            validator_address: addr,
            validator_signature: Signature::ZERO,
        }
        .sign(kp);
        let second = Precommit {
            block_hash: Some(Hash32::from_bytes([0x02; 32])),
            validator_signature: Signature::ZERO,
            ..base
        }
        .sign(kp);

        Evidence {
            version: sango_types::PROTOCOL_VERSION_V1,
            evidence_type: EvidenceType::DoublePrecommit,
            chain_id: chain(),
            epoch: Epoch::new(0),
            height: Height::new(100),
            round: Round::new(0),
            validator_address: addr,
            message_1: ConsensusMessage {
                message_type: ConsensusMessageType::Precommit,
                canonical_payload: base.encode_unsigned_to_vec(),
                signature: base.validator_signature,
            },
            message_2: ConsensusMessage {
                message_type: ConsensusMessageType::Precommit,
                canonical_payload: second.encode_unsigned_to_vec(),
                signature: second.validator_signature,
            },
        }
    }

    // --- Cas heureux --------------------------------------------------------

    #[test]
    fn slash_5_percent_of_self_stake() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let addr = derive_native_address(&kp.public_key());
        let mut state = NativeState::new();
        state.set_validator(validator_info(addr, kp.public_key(), 100_000));

        let ev = make_double_prevote(&kp);
        let r = apply_evidence(&mut state, &ev, &ctx()).unwrap();

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
    fn double_precommit_also_slashes() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let addr = derive_native_address(&kp.public_key());
        let mut state = NativeState::new();
        state.set_validator(validator_info(addr, kp.public_key(), 100_000));

        let ev = make_double_precommit(&kp);
        let r = apply_evidence(&mut state, &ev, &ctx()).unwrap();
        assert_eq!(r.slashed_self, Amount::from_sango(5_000).unwrap());
    }

    #[test]
    fn slash_also_reduces_delegations() {
        use sango_types::Delegation;
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let addr = derive_native_address(&kp.public_key());
        let mut state = NativeState::new();

        let mut info = validator_info(addr, kp.public_key(), 100_000);
        info.total_delegated = Amount::from_sango(50_000).unwrap();
        state.set_validator(info);

        let mut d1 = Delegation::empty(NativeAddress::from_bytes([0x01; 20]), addr);
        d1.bonded = Amount::from_sango(30_000).unwrap();
        state.set_delegation(d1);

        let mut d2 = Delegation::empty(NativeAddress::from_bytes([0x02; 20]), addr);
        d2.bonded = Amount::from_sango(20_000).unwrap();
        state.set_delegation(d2);

        let ev = make_double_prevote(&kp);
        let r = apply_evidence(&mut state, &ev, &ctx()).unwrap();

        assert_eq!(r.slashed_self, Amount::from_sango(5_000).unwrap());
        assert_eq!(r.slashed_delegated, Amount::from_sango(2_500).unwrap());
    }

    // --- Rejets -------------------------------------------------------------

    #[test]
    fn double_application_rejected() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let addr = derive_native_address(&kp.public_key());
        let mut state = NativeState::new();
        state.set_validator(validator_info(addr, kp.public_key(), 100_000));

        let ev = make_double_prevote(&kp);
        apply_evidence(&mut state, &ev, &ctx()).unwrap();

        let err = apply_evidence(&mut state, &ev, &ctx()).unwrap_err();
        assert!(matches!(err, ApplyError::EvidenceAlreadyApplied(_)));
    }

    #[test]
    fn unknown_validator_rejected() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let mut state = NativeState::new();
        let ev = make_double_prevote(&kp);
        let err = apply_evidence(&mut state, &ev, &ctx()).unwrap_err();
        assert!(matches!(err, ApplyError::ValidatorNotFound(_)));
    }

    #[test]
    fn wrong_signature_rejected() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let other = NativeKeypair::from_seed([0x43; 32]);
        let addr = derive_native_address(&kp.public_key());

        let mut state = NativeState::new();
        state.set_validator(validator_info(addr, kp.public_key(), 100_000));

        // Evidence signée par `other` (clé différente).
        let mut ev = make_double_prevote(&other);
        ev.validator_address = addr; // l'adresse déclarée est bien celle du validateur
        let err = apply_evidence(&mut state, &ev, &ctx()).unwrap_err();
        assert!(
            matches!(err, ApplyError::InvalidEvidence("invalid signature")),
            "got: {err:?}"
        );
    }

    #[test]
    fn non_contradictory_rejected() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let addr = derive_native_address(&kp.public_key());
        let mut state = NativeState::new();
        state.set_validator(validator_info(addr, kp.public_key(), 100_000));

        // Deux fois le même block_hash.
        let p = Prevote {
            chain_id: chain(),
            epoch: Epoch::new(0),
            height: Height::new(100),
            round: Round::new(0),
            block_hash: Some(Hash32::from_bytes([0x01; 32])),
            validator_address: addr,
            validator_signature: Signature::ZERO,
        }
        .sign(&kp);

        let ev = Evidence {
            version: sango_types::PROTOCOL_VERSION_V1,
            evidence_type: EvidenceType::DoublePrevote,
            chain_id: chain(),
            epoch: Epoch::new(0),
            height: Height::new(100),
            round: Round::new(0),
            validator_address: addr,
            message_1: ConsensusMessage {
                message_type: ConsensusMessageType::Prevote,
                canonical_payload: p.encode_unsigned_to_vec(),
                signature: p.validator_signature,
            },
            message_2: ConsensusMessage {
                message_type: ConsensusMessageType::Prevote,
                canonical_payload: p.encode_unsigned_to_vec(),
                signature: p.validator_signature,
            },
        };
        let err = apply_evidence(&mut state, &ev, &ctx()).unwrap_err();
        assert!(
            matches!(
                err,
                ApplyError::InvalidEvidence("messages are not contradictory")
            ),
            "got: {err:?}"
        );
    }

    #[test]
    fn wrong_message_type_rejected() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let addr = derive_native_address(&kp.public_key());
        let mut state = NativeState::new();
        state.set_validator(validator_info(addr, kp.public_key(), 100_000));

        // Evidence déclarée DoublePrevote mais message de type Precommit.
        let mut ev = make_double_prevote(&kp);
        ev.message_1.message_type = ConsensusMessageType::Precommit;
        let err = apply_evidence(&mut state, &ev, &ctx()).unwrap_err();
        assert!(
            matches!(
                err,
                ApplyError::InvalidEvidence("message type does not match evidence type")
            ),
            "got: {err:?}"
        );
    }

    #[test]
    fn evidence_recorded_in_state() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let addr = derive_native_address(&kp.public_key());
        let mut state = NativeState::new();
        state.set_validator(validator_info(addr, kp.public_key(), 100_000));

        let ev = make_double_prevote(&kp);
        let evidence_id = ev.evidence_id();
        assert!(!state.has_evidence(&evidence_id));

        apply_evidence(&mut state, &ev, &ctx()).unwrap();
        assert!(state.has_evidence(&evidence_id));

        let rec = state.get_evidence(&evidence_id).unwrap();
        assert_eq!(rec.validator_address, addr);
        assert_eq!(rec.applied_at_height, 1);
    }
}
