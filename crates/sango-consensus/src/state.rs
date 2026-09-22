//! État local de consensus d'un validateur (lock / valid).
//!
//! Freeze sections 40 à 42.

use sango_primitives::{Hash32, Height, Round};

/// Résultat de l'observation d'un PoLC.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolcOutcome {
    /// Le premier PoLC a établi un lock.
    Locked,
    /// Le PoLC a remplacé un lock précédent sur un bloc différent.
    UnlockedAndLocked,
    /// Le PoLC a remplacé un lock sur le **même** bloc à un round inférieur.
    Upgraded,
    /// Le PoLC a été ignoré (round ≤ locked_round).
    Ignored,
}

/// État local de consensus d'un validateur à une hauteur donnée.
///
/// ## Sémantique
///
/// - `locked_block_hash = None` ↔ NIL (aucun lock).
/// - `locked_round = None` ↔ `-1` (aucun lock).
/// - Idem pour `valid_block_hash` et `valid_round`.
///
/// ## Invariants
///
/// - Un **timeout** ne modifie **jamais** l'état de lock : c'est au driver
///   de gérer les timeouts sans toucher à `ConsensusState`.
/// - Le lock ne peut être remplacé que par un PoLC d'un **autre** bloc à un
///   round **strictement supérieur** (Freeze section 10.7).

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsensusState {
    height: Height,
    round: Round,
    locked_block_hash: Option<Hash32>,
    locked_round: Option<Round>,
    valid_block_hash: Option<Hash32>,
    valid_round: Option<Round>,
}

impl ConsensusState {
    /// Initialise un état à une hauteur, sans aucun lock.
    #[must_use]
    pub fn new(height: Height) -> Self {
        Self {
            height,
            round: Round::new(0),
            locked_block_hash: None,
            locked_round: None,
            valid_block_hash: None,
            valid_round: None,
        }
    }

    /// Hauteur courante.
    #[must_use]
    pub fn height(&self) -> Height {
        self.height
    }

    /// Round courant.
    #[must_use]
    pub fn round(&self) -> Round {
        self.round
    }

    /// Lock courant, si présent.
    #[must_use]
    pub fn locked(&self) -> Option<(Hash32, Round)> {
        match (self.locked_block_hash, self.locked_round) {
            (Some(bh), Some(r)) => Some((bh, r)),
            _ => None,
        }
    }

    /// Valid courant, si présent.
    #[must_use]
    pub fn valid(&self) -> Option<(Hash32, Round)> {
        match (self.valid_block_hash, self.valid_round) {
            (Some(bh), Some(r)) => Some((bh, r)),
            _ => None,
        }
    }

    /// Met à jour le round courant.
    ///
    /// Cette opération ne touche pas aux locks : un changement de round ne
    /// déverrouille jamais (Freeze section 10.5).
    pub fn set_round(&mut self, round: Round) {
        self.round = round;
    }

    /// Passe à une nouvelle hauteur et réinitialise tous les locks.
    ///
    /// À n'appeler que lorsque le consensus a décidé du bloc final à la
    /// hauteur précédente.
    pub fn advance_height(&mut self, height: Height) {
        self.height = height;
        self.round = Round::new(0);
        self.locked_block_hash = None;
        self.locked_round = None;
        self.valid_block_hash = None;
        self.valid_round = None;
    }

    /// Applique l'observation d'un PoLC pour `(block_hash, round)`.
    ///
    /// C'est à l'appelant de vérifier que le PoLC est bien formé (quorum,
    /// signatures, contexte) avant d'appeler cette méthode.
    ///
    /// ## Règles (Freeze section 10.7)
    ///
    /// - Pas de lock actuel → lock + valid sur `(block_hash, round)`.
    /// - Lock actuel `(A, r_A)` avec `round > r_A` → lock + valid sur
    ///   `(block_hash, round)`. `UnlockedAndLocked` si `A != block_hash`,
    ///   `Upgraded` sinon.
    /// - Lock actuel `(A, r_A)` avec `round <= r_A` → ignoré.
    pub fn observe_polc(&mut self, block_hash: Hash32, round: Round) -> PolcOutcome {
        match (self.locked_block_hash, self.locked_round) {
            (None, _) => {
                self.locked_block_hash = Some(block_hash);
                self.locked_round = Some(round);
                self.valid_block_hash = Some(block_hash);
                self.valid_round = Some(round);
                PolcOutcome::Locked
            }
            (Some(old_bh), Some(old_r)) => {
                if round <= old_r {
                    PolcOutcome::Ignored
                } else {
                    self.locked_block_hash = Some(block_hash);
                    self.locked_round = Some(round);
                    self.valid_block_hash = Some(block_hash);
                    self.valid_round = Some(round);
                    if old_bh == block_hash {
                        PolcOutcome::Upgraded
                    } else {
                        PolcOutcome::UnlockedAndLocked
                    }
                }
            }
            // Invariant cassé : ne devrait jamais arriver.
            _ => PolcOutcome::Ignored,
        }
    }

    /// Décide de la cible du prevote étant donné la proposition observée.
    ///
    /// ## Règles (Freeze section 10.9)
    ///
    /// - Pas de lock → prevote la proposition (ou NIL).
    /// - Lock sur le même bloc que la proposition → prevote ce bloc.
    /// - Lock sur un autre bloc → prevote NIL.
    ///
    /// ## Note importante
    ///
    /// Si le validateur a déjà observé un PoLC qui justifie un déverrouillage
    /// (via `observe_polc`), le lock a été mis à jour en amont ; cette
    /// fonction n'a pas à le refaire.
    #[must_use]
    pub fn decide_prevote(&self, proposed_block_hash: Option<Hash32>) -> Option<Hash32> {
        match (self.locked_block_hash, proposed_block_hash) {
            (None, _) => proposed_block_hash,
            (Some(locked), None) => {
                // Lock sur un bloc, mais proposition NIL : on ne peut pas
                // voter pour le bloc verrouillé sans proposition. Prevote NIL.
                let _ = locked;
                None
            }
            (Some(locked), Some(proposed)) if locked == proposed => Some(locked),
            (Some(_), Some(_)) => None,
        }
    }

    /// Vrai si le validateur peut precommit `block_hash`.
    ///
    /// ## Règle (Freeze section 10.10)
    ///
    /// Un validateur ne peut precommit que :
    ///
    /// - NIL (`block_hash == None`) ;
    /// - ou un bloc pour lequel il a observé un PoLC (donc `valid_block_hash`).
    #[must_use]
    pub fn can_precommit(&self, block_hash: Option<Hash32>) -> bool {
        match (block_hash, self.valid_block_hash) {
            (None, _) => true,
            (Some(bh), Some(valid)) => bh == valid,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(b: u8) -> Hash32 {
        Hash32::from_bytes([b; 32])
    }

    #[test]
    fn initial_state_has_no_lock() {
        let s = ConsensusState::new(Height::new(1));
        assert_eq!(s.locked(), None);
        assert_eq!(s.valid(), None);
        assert_eq!(s.round(), Round::new(0));
    }

    #[test]
    fn observe_polc_first_time_locks() {
        let mut s = ConsensusState::new(Height::new(1));
        assert_eq!(s.observe_polc(h(1), Round::new(0)), PolcOutcome::Locked);
        assert_eq!(s.locked(), Some((h(1), Round::new(0))));
        assert_eq!(s.valid(), Some((h(1), Round::new(0))));
    }

    #[test]
    fn observe_polc_same_block_higher_round_upgrades() {
        let mut s = ConsensusState::new(Height::new(1));
        s.observe_polc(h(1), Round::new(0));
        assert_eq!(s.observe_polc(h(1), Round::new(1)), PolcOutcome::Upgraded);
        assert_eq!(s.locked(), Some((h(1), Round::new(1))));
    }

    #[test]
    fn observe_polc_different_block_higher_round_unlocks() {
        let mut s = ConsensusState::new(Height::new(1));
        s.observe_polc(h(1), Round::new(0));
        assert_eq!(
            s.observe_polc(h(2), Round::new(1)),
            PolcOutcome::UnlockedAndLocked
        );
        assert_eq!(s.locked(), Some((h(2), Round::new(1))));
    }

    #[test]
    fn observe_polc_different_block_same_round_is_ignored() {
        let mut s = ConsensusState::new(Height::new(1));
        s.observe_polc(h(1), Round::new(0));
        assert_eq!(s.observe_polc(h(2), Round::new(0)), PolcOutcome::Ignored);
        assert_eq!(s.locked(), Some((h(1), Round::new(0))));
    }

    #[test]
    fn observe_polc_different_block_lower_round_is_ignored() {
        let mut s = ConsensusState::new(Height::new(1));
        s.observe_polc(h(1), Round::new(5));
        assert_eq!(s.observe_polc(h(2), Round::new(3)), PolcOutcome::Ignored);
        assert_eq!(s.locked(), Some((h(1), Round::new(5))));
    }

    #[test]
    fn timeout_does_not_unlock() {
        // Un simple set_round ne déverrouille pas.
        let mut s = ConsensusState::new(Height::new(1));
        s.observe_polc(h(1), Round::new(0));
        s.set_round(Round::new(1));
        assert_eq!(s.locked(), Some((h(1), Round::new(0))));
    }

    #[test]
    fn advance_height_clears_locks() {
        let mut s = ConsensusState::new(Height::new(1));
        s.observe_polc(h(1), Round::new(0));
        s.advance_height(Height::new(2));
        assert_eq!(s.height(), Height::new(2));
        assert_eq!(s.round(), Round::new(0));
        assert_eq!(s.locked(), None);
        assert_eq!(s.valid(), None);
    }

    #[test]
    fn decide_prevote_no_lock_votes_proposal() {
        let s = ConsensusState::new(Height::new(1));
        assert_eq!(s.decide_prevote(Some(h(1))), Some(h(1)));
        assert_eq!(s.decide_prevote(None), None);
    }

    #[test]
    fn decide_prevote_locked_same_block_votes_it() {
        let mut s = ConsensusState::new(Height::new(1));
        s.observe_polc(h(1), Round::new(0));
        assert_eq!(s.decide_prevote(Some(h(1))), Some(h(1)));
    }

    #[test]
    fn decide_prevote_locked_different_block_votes_nil() {
        let mut s = ConsensusState::new(Height::new(1));
        s.observe_polc(h(1), Round::new(0));
        assert_eq!(s.decide_prevote(Some(h(2))), None);
    }

    #[test]
    fn decide_prevote_locked_nil_proposal_votes_nil() {
        let mut s = ConsensusState::new(Height::new(1));
        s.observe_polc(h(1), Round::new(0));
        assert_eq!(s.decide_prevote(None), None);
    }

    #[test]
    fn can_precommit_nil_always() {
        let s = ConsensusState::new(Height::new(1));
        assert!(s.can_precommit(None));
    }

    #[test]
    fn can_precommit_valid_block() {
        let mut s = ConsensusState::new(Height::new(1));
        s.observe_polc(h(1), Round::new(0));
        assert!(s.can_precommit(Some(h(1))));
        assert!(!s.can_precommit(Some(h(2))));
    }

    #[test]
    fn can_precommit_no_valid_no_lock() {
        let s = ConsensusState::new(Height::new(1));
        assert!(!s.can_precommit(Some(h(1))));
    }
}
