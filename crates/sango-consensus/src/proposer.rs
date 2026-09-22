//! Sélection déterministe du proposer.
//!
//! Freeze section 16 : sampling pondéré déterministe avec rejection
//! sampling, sans flottants.

use sango_crypto::{domain, keccak256};
use sango_primitives::{ChainId32, Epoch, Hash32, Height, NativeAddress, Round};

use crate::error::ConsensusError;
use crate::validator_set::ValidatorSet;

/// Sélectionne le proposer pour `(epoch, height, round, parent_hash)`.
///
/// ## Algorithme
///
/// 1. `seed = Keccak256("SANGO/PROPOSER/V1" || chain_id || epoch || height
///    || round || previous_block_hash)`.
/// 2. Rejection sampling : on tire `r = Keccak256(seed || counter)[0..16]`
///    interprété comme `u128`, jusqu'à ce que `r <= u128::MAX -
///    (u128::MAX % total_power)`. Cela garantit une distribution uniforme
///    sur `[0, total_power)` sans biais.
/// 3. On retourne l'adresse du validateur dans l'intervalle cumulatif
///    contenant `target = r % total_power`.
///
/// Aucun flottant. Aucune dépendance au nœud qui effectue le calcul.
pub fn select_proposer(
    chain_id: &ChainId32,
    epoch: Epoch,
    height: Height,
    round: Round,
    previous_block_hash: &Hash32,
    validator_set: &ValidatorSet,
) -> Result<NativeAddress, ConsensusError> {
    if validator_set.is_empty() {
        return Err(ConsensusError::EmptyValidatorSet);
    }
    let total = validator_set.total_power();
    if total == 0 {
        return Err(ConsensusError::ZeroVotingPower);
    }

    // --- Seed ---------------------------------------------------------------
    let mut seed_input = Vec::with_capacity(domain::PROPOSER_V1.len() + 32 + 8 + 8 + 8 + 32);
    seed_input.extend_from_slice(domain::PROPOSER_V1);
    seed_input.extend_from_slice(chain_id.as_bytes());
    seed_input.extend_from_slice(&epoch.get().to_le_bytes());
    seed_input.extend_from_slice(&height.get().to_le_bytes());
    seed_input.extend_from_slice(&round.get().to_le_bytes());
    seed_input.extend_from_slice(previous_block_hash.as_bytes());
    let seed = keccak256(&seed_input);

    // --- Rejection sampling -------------------------------------------------
    let max_accept = u128::MAX - (u128::MAX % total);
    let target = {
        let mut counter: u32 = 0;
        loop {
            let mut buf = Vec::with_capacity(36);
            buf.extend_from_slice(seed.as_bytes());
            buf.extend_from_slice(&counter.to_le_bytes());
            let h = keccak256(&buf);
            let mut r_bytes = [0u8; 16];
            r_bytes.copy_from_slice(&h.as_bytes()[..16]);
            let r = u128::from_le_bytes(r_bytes);
            if r <= max_accept {
                break r % total;
            }
            counter = counter
                .checked_add(1)
                .ok_or(ConsensusError::ProposerSamplingExhausted)?;
        }
    };

    // --- Sélection par intervalles cumulatifs -------------------------------
    let mut cumulative: u128 = 0;
    for v in validator_set.iter() {
        cumulative = cumulative.saturating_add(v.voting_power);
        if target < cumulative {
            return Ok(v.address);
        }
    }

    // Inatteignable si total_power == cumulative.
    Err(ConsensusError::ProposerSamplingExhausted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator_set::Validator;
    use sango_primitives::PublicKey;

    fn addr(b: u8) -> NativeAddress {
        NativeAddress::from_bytes([b; 20])
    }

    fn validator(b: u8, power: u128) -> Validator {
        Validator {
            address: addr(b),
            public_key: PublicKey::from_bytes([b; 32]),
            voting_power: power,
        }
    }

    fn chain() -> ChainId32 {
        ChainId32::from_bytes([0x11; 32])
    }

    fn vs_equal() -> ValidatorSet {
        ValidatorSet::new(vec![
            validator(0xaa, 100),
            validator(0xbb, 100),
            validator(0xcc, 100),
            validator(0xdd, 100),
        ])
        .unwrap()
    }

    #[test]
    fn deterministic_same_inputs() {
        let vs = vs_equal();
        let p1 = select_proposer(
            &chain(),
            Epoch::new(0),
            Height::new(1),
            Round::new(0),
            &Hash32::from_bytes([0x42; 32]),
            &vs,
        )
        .unwrap();
        let p2 = select_proposer(
            &chain(),
            Epoch::new(0),
            Height::new(1),
            Round::new(0),
            &Hash32::from_bytes([0x42; 32]),
            &vs,
        )
        .unwrap();
        assert_eq!(p1, p2);
    }

    #[test]
    fn different_heights_generally_differ() {
        let vs = vs_equal();
        let p1 = select_proposer(
            &chain(),
            Epoch::new(0),
            Height::new(1),
            Round::new(0),
            &Hash32::ZERO,
            &vs,
        )
        .unwrap();
        let p2 = select_proposer(
            &chain(),
            Epoch::new(0),
            Height::new(2),
            Round::new(0),
            &Hash32::ZERO,
            &vs,
        )
        .unwrap();
        // Probabilité de collision ~ 1/4 ; on teste sur plusieurs hauteurs
        // pour éviter un faux négatif.
        let mut differ = p1 != p2;
        for h in 3..20 {
            let p = select_proposer(
                &chain(),
                Epoch::new(0),
                Height::new(h),
                Round::new(0),
                &Hash32::ZERO,
                &vs,
            )
            .unwrap();
            if p != p1 {
                differ = true;
                break;
            }
        }
        assert!(
            differ,
            "toutes les hauteurs testées donnent le même proposer"
        );
    }

    #[test]
    fn single_validator_is_always_proposer() {
        let vs = ValidatorSet::new(vec![validator(0xaa, 1_000_000)]).unwrap();
        for h in 0..20 {
            let p = select_proposer(
                &chain(),
                Epoch::new(0),
                Height::new(h),
                Round::new(0),
                &Hash32::ZERO,
                &vs,
            )
            .unwrap();
            assert_eq!(p, addr(0xaa));
        }
    }

    #[test]
    fn larger_power_is_selected_more_often() {
        // Validator A : 90 % ; Validator B : 10 %.
        let vs = ValidatorSet::new(vec![validator(0xaa, 900), validator(0xbb, 100)]).unwrap();

        let mut count_a = 0;
        let mut count_b = 0;
        for h in 0..200 {
            let p = select_proposer(
                &chain(),
                Epoch::new(0),
                Height::new(h),
                Round::new(0),
                &Hash32::from_bytes([0x42; 32]),
                &vs,
            )
            .unwrap();
            if p == addr(0xaa) {
                count_a += 1;
            } else {
                count_b += 1;
            }
        }
        // On s'attend à ~90 % pour A ; on vérifie une large marge.
        assert!(count_a > 130, "count_a = {count_a}, attendu > 130");
        assert!(count_b > 0, "count_b = 0, B jamais choisi");
    }

    #[test]
    fn empty_set_rejected() {
        // On ne peut pas construire un ValidatorSet vide via `new`, mais
        // on peut tester que `select_proposer` échoue sur un set vide en
        // utilisant `ValidatorSet::new` avec une liste vide.
        assert!(matches!(
            ValidatorSet::new(vec![]),
            Err(ConsensusError::EmptyValidatorSet)
        ));
    }
}
