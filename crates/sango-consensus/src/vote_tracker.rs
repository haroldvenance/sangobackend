//! Accumulation des votes et construction des certificats.
//!
//! Le tracker est lié à un contexte `(chain_id, epoch, height, round)`.

use std::collections::{BTreeMap, HashMap};

use sango_primitives::{ChainId32, Epoch, Hash32, Height, NativeAddress, Round};
use sango_types::{
    CommitCertificate, Precommit, PrecommitEntry, Prevote, PrevoteCertificate, PrevoteEntry,
};

use crate::error::ConsensusError;
use crate::validator_set::ValidatorSet;

/// Version des certificats produits.
const CERT_VERSION: u32 = 1;

/// Accumulateur de votes pour un `(height, round)` précis.
pub struct VoteTracker {
    chain_id: ChainId32,
    epoch: Epoch,
    height: Height,
    round: Round,

    first_prevote: HashMap<NativeAddress, Prevote>,
    prevotes_by_block: BTreeMap<Option<Hash32>, Vec<PrevoteEntry>>,
    prevote_power: BTreeMap<Option<Hash32>, u128>,

    first_precommit: HashMap<NativeAddress, Precommit>,
    precommits_by_block: BTreeMap<Option<Hash32>, Vec<PrecommitEntry>>,
    precommit_power: BTreeMap<Option<Hash32>, u128>,
}

impl VoteTracker {
    /// Crée un tracker pour le contexte donné.
    #[must_use]
    pub fn new(chain_id: ChainId32, epoch: Epoch, height: Height, round: Round) -> Self {
        Self {
            chain_id,
            epoch,
            height,
            round,
            first_prevote: HashMap::new(),
            prevotes_by_block: BTreeMap::new(),
            prevote_power: BTreeMap::new(),
            first_precommit: HashMap::new(),
            precommits_by_block: BTreeMap::new(),
            precommit_power: BTreeMap::new(),
        }
    }

    /// Chain ID du tracker.
    #[must_use]
    pub fn chain_id(&self) -> ChainId32 {
        self.chain_id
    }

    /// Epoch du tracker.
    #[must_use]
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Hauteur du tracker.
    #[must_use]
    pub fn height(&self) -> Height {
        self.height
    }

    /// Round du tracker.
    #[must_use]
    pub fn round(&self) -> Round {
        self.round
    }

    // --- Prevotes -----------------------------------------------------------

    /// Ajoute une prevote.
    ///
    /// ## Comportement
    ///
    /// - Vérifie le contexte (`chain_id`, `epoch`, `height`, `round`).
    /// - Vérifie que le validateur est connu et que la signature est valide.
    /// - Ignore les doublons (même validateur, même `block_hash`).
    /// - Rejette les double-votes (même validateur, `block_hash` différent).
    pub fn add_prevote(
        &mut self,
        prevote: Prevote,
        vs: &ValidatorSet,
    ) -> Result<(), ConsensusError> {
        self.verify_prevote_context(&prevote)?;

        let validator = vs
            .get(&prevote.validator_address)
            .ok_or(ConsensusError::UnknownValidator(prevote.validator_address))?;
        prevote
            .verify(&validator.public_key)
            .map_err(|_| ConsensusError::InvalidSignature(prevote.validator_address))?;

        if let Some(previous) = self.first_prevote.get(&prevote.validator_address) {
            if previous.block_hash == prevote.block_hash {
                return Ok(()); // doublon exact
            }
            return Err(ConsensusError::DoublePrevote {
                address: prevote.validator_address,
                first: Box::new(*previous),
                second: Box::new(prevote),
            });
        }

        self.first_prevote
            .insert(prevote.validator_address, prevote);
        self.prevotes_by_block
            .entry(prevote.block_hash)
            .or_default()
            .push(PrevoteEntry {
                validator_address: prevote.validator_address,
                signature: prevote.validator_signature,
            });
        let entry = self.prevote_power.entry(prevote.block_hash).or_insert(0);
        *entry = entry.saturating_add(validator.voting_power);

        Ok(())
    }

    /// Retourne le `PrevoteCertificate` pour `block_hash` si le quorum est
    /// atteint, sinon `None`.
    #[must_use]
    pub fn prevote_certificate(
        &self,
        block_hash: Option<Hash32>,
        vs: &ValidatorSet,
    ) -> Option<PrevoteCertificate> {
        let power = self.prevote_power.get(&block_hash).copied().unwrap_or(0);
        if !vs.has_quorum(power) {
            return None;
        }
        let mut prevotes = self
            .prevotes_by_block
            .get(&block_hash)
            .cloned()
            .unwrap_or_default();
        prevotes.sort_by_key(|e| e.validator_address);
        Some(PrevoteCertificate {
            version: CERT_VERSION,
            chain_id: self.chain_id,
            epoch: self.epoch,
            height: self.height,
            round: self.round,
            block_hash,
            prevotes,
        })
    }

    /// Puissance cumulée des prevotes pour `block_hash`.
    #[must_use]
    pub fn prevote_power_for(&self, block_hash: Option<Hash32>) -> u128 {
        self.prevote_power.get(&block_hash).copied().unwrap_or(0)
    }

    // --- Precommits ---------------------------------------------------------

    /// Ajoute un precommit.
    ///
    /// Mêmes règles que pour les prevotes.
    pub fn add_precommit(
        &mut self,
        precommit: Precommit,
        vs: &ValidatorSet,
    ) -> Result<(), ConsensusError> {
        self.verify_precommit_context(&precommit)?;

        let validator =
            vs.get(&precommit.validator_address)
                .ok_or(ConsensusError::UnknownValidator(
                    precommit.validator_address,
                ))?;
        precommit
            .verify(&validator.public_key)
            .map_err(|_| ConsensusError::InvalidSignature(precommit.validator_address))?;

        if let Some(previous) = self.first_precommit.get(&precommit.validator_address) {
            if previous.block_hash == precommit.block_hash {
                return Ok(());
            }
            return Err(ConsensusError::DoublePrecommit {
                address: precommit.validator_address,
                first: Box::new(*previous),
                second: Box::new(precommit),
            });
        }

        self.first_precommit
            .insert(precommit.validator_address, precommit);
        self.precommits_by_block
            .entry(precommit.block_hash)
            .or_default()
            .push(PrecommitEntry {
                validator_address: precommit.validator_address,
                signature: precommit.validator_signature,
            });
        let entry = self
            .precommit_power
            .entry(precommit.block_hash)
            .or_insert(0);
        *entry = entry.saturating_add(validator.voting_power);

        Ok(())
    }

    /// Retourne le `CommitCertificate` pour `block_hash` si le quorum est
    /// atteint, sinon `None`.
    ///
    /// `block_hash` est **non-NIL** : un commit ne peut porter que sur un
    /// bloc réel.
    #[must_use]
    pub fn commit_certificate(
        &self,
        block_hash: Hash32,
        vs: &ValidatorSet,
    ) -> Option<CommitCertificate> {
        let power = self
            .precommit_power
            .get(&Some(block_hash))
            .copied()
            .unwrap_or(0);
        if !vs.has_quorum(power) {
            return None;
        }
        let mut precommits = self
            .precommits_by_block
            .get(&Some(block_hash))
            .cloned()
            .unwrap_or_default();
        precommits.sort_by_key(|e| e.validator_address);
        Some(CommitCertificate {
            version: CERT_VERSION,
            chain_id: self.chain_id,
            epoch: self.epoch,
            height: self.height,
            round: self.round,
            block_hash,
            precommits,
        })
    }

    /// Puissance cumulée des precommits pour `block_hash`.
    #[must_use]
    pub fn precommit_power_for(&self, block_hash: Option<Hash32>) -> u128 {
        self.precommit_power.get(&block_hash).copied().unwrap_or(0)
    }

    /// Vrai si le validateur a déjà voté une prevote (utile au driver).
    #[must_use]
    pub fn has_prevoted(&self, address: &NativeAddress) -> bool {
        self.first_prevote.contains_key(address)
    }

    /// Vrai si le validateur a déjà voté un precommit (utile au driver).
    #[must_use]
    pub fn has_precommitted(&self, address: &NativeAddress) -> bool {
        self.first_precommit.contains_key(address)
    }

    // --- Helpers privés -----------------------------------------------------

    fn verify_prevote_context(&self, p: &Prevote) -> Result<(), ConsensusError> {
        if p.chain_id != self.chain_id {
            return Err(ConsensusError::ChainIdMismatch {
                expected: self.chain_id,
                got: p.chain_id,
            });
        }
        if p.epoch != self.epoch {
            return Err(ConsensusError::EpochMismatch {
                expected: self.epoch,
                got: p.epoch,
            });
        }
        if p.height != self.height {
            return Err(ConsensusError::HeightMismatch {
                expected: self.height,
                got: p.height,
            });
        }
        if p.round != self.round {
            return Err(ConsensusError::RoundMismatch {
                expected: self.round,
                got: p.round,
            });
        }
        Ok(())
    }

    fn verify_precommit_context(&self, p: &Precommit) -> Result<(), ConsensusError> {
        if p.chain_id != self.chain_id {
            return Err(ConsensusError::ChainIdMismatch {
                expected: self.chain_id,
                got: p.chain_id,
            });
        }
        if p.epoch != self.epoch {
            return Err(ConsensusError::EpochMismatch {
                expected: self.epoch,
                got: p.epoch,
            });
        }
        if p.height != self.height {
            return Err(ConsensusError::HeightMismatch {
                expected: self.height,
                got: p.height,
            });
        }
        if p.round != self.round {
            return Err(ConsensusError::RoundMismatch {
                expected: self.round,
                got: p.round,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator_set::Validator;
    use sango_crypto::{derive_native_address, NativeKeypair};
    use sango_primitives::Signature;

    fn chain() -> ChainId32 {
        ChainId32::from_bytes([0x11; 32])
    }

    fn hash(b: u8) -> Hash32 {
        Hash32::from_bytes([b; 32])
    }

    /// Crée un validator set avec `n` validateurs, chacun avec la clé dérivée
    /// d'une seed `[i; 32]` et un voting power de 100.
    fn make_set(n: u8) -> (Vec<NativeKeypair>, ValidatorSet) {
        let mut keypairs = Vec::new();
        let mut validators = Vec::new();
        for i in 0..n {
            let kp = NativeKeypair::from_seed([i + 1; 32]);
            let pk = kp.public_key();
            let address = derive_native_address(&pk);
            validators.push(Validator {
                address,
                public_key: pk,
                voting_power: 100,
            });
            keypairs.push(kp);
        }
        (keypairs, ValidatorSet::new(validators).unwrap())
    }

    fn make_prevote(kp: &NativeKeypair, block_hash: Option<Hash32>) -> Prevote {
        let pk = kp.public_key();
        let address = derive_native_address(&pk);
        let p = Prevote {
            chain_id: chain(),
            epoch: Epoch::new(0),
            height: Height::new(1),
            round: Round::new(0),
            block_hash,
            validator_address: address,
            validator_signature: Signature::ZERO,
        };
        p.sign(kp)
    }

    fn make_precommit(kp: &NativeKeypair, block_hash: Option<Hash32>) -> Precommit {
        let pk = kp.public_key();
        let address = derive_native_address(&pk);
        let p = Precommit {
            chain_id: chain(),
            epoch: Epoch::new(0),
            height: Height::new(1),
            round: Round::new(0),
            block_hash,
            validator_address: address,
            validator_signature: Signature::ZERO,
        };
        p.sign(kp)
    }

    fn tracker() -> VoteTracker {
        VoteTracker::new(chain(), Epoch::new(0), Height::new(1), Round::new(0))
    }

    // --- Prevote -----------------------------------------------------------

    #[test]
    fn add_prevote_ok() {
        let (kps, vs) = make_set(4);
        let mut t = tracker();
        t.add_prevote(make_prevote(&kps[0], Some(hash(1))), &vs)
            .unwrap();
        assert_eq!(t.prevote_power_for(Some(hash(1))), 100);
        assert!(t.has_prevoted(&derive_native_address(&kps[0].public_key())));
    }

    #[test]
    fn add_prevote_duplicate_is_ignored() {
        let (kps, vs) = make_set(4);
        let mut t = tracker();
        let p = make_prevote(&kps[0], Some(hash(1)));
        t.add_prevote(p, &vs).unwrap();
        t.add_prevote(p, &vs).unwrap();
        assert_eq!(t.prevote_power_for(Some(hash(1))), 100);
    }

    #[test]
    fn add_prevote_double_vote_rejected() {
        let (kps, vs) = make_set(4);
        let mut t = tracker();
        t.add_prevote(make_prevote(&kps[0], Some(hash(1))), &vs)
            .unwrap();
        let err = t
            .add_prevote(make_prevote(&kps[0], Some(hash(2))), &vs)
            .unwrap_err();
        assert!(matches!(err, ConsensusError::DoublePrevote { .. }));
    }

    #[test]
    fn add_prevote_wrong_round_rejected() {
        let (kps, vs) = make_set(4);
        let mut t = tracker();
        let pk = kps[0].public_key();
        let mut p = Prevote {
            chain_id: chain(),
            epoch: Epoch::new(0),
            height: Height::new(1),
            round: Round::new(1), // mauvais
            block_hash: Some(hash(1)),
            validator_address: derive_native_address(&pk),
            validator_signature: Signature::ZERO,
        };
        p = p.sign(&kps[0]);
        let err = t.add_prevote(p, &vs).unwrap_err();
        assert!(matches!(err, ConsensusError::RoundMismatch { .. }));
    }

    #[test]
    fn add_prevote_unknown_validator_rejected() {
        let (kps, vs) = make_set(4);
        let mut t = tracker();
        let stranger = NativeKeypair::from_seed([0xff; 32]);
        let pk = stranger.public_key();
        let mut p = Prevote {
            chain_id: chain(),
            epoch: Epoch::new(0),
            height: Height::new(1),
            round: Round::new(0),
            block_hash: Some(hash(1)),
            validator_address: derive_native_address(&pk),
            validator_signature: Signature::ZERO,
        };
        p = p.sign(&stranger);
        let err = t.add_prevote(p, &vs).unwrap_err();
        assert!(matches!(err, ConsensusError::UnknownValidator(_)));
        let _ = kps;
    }

    #[test]
    fn add_prevote_bad_signature_rejected() {
        let (kps, vs) = make_set(4);
        let mut t = tracker();
        let p = make_prevote(&kps[0], Some(hash(1)));
        // Modifier le block_hash après signature invalide la signature.
        let mut tampered = p;
        tampered.block_hash = Some(hash(2));
        let err = t.add_prevote(tampered, &vs).unwrap_err();
        assert!(matches!(err, ConsensusError::InvalidSignature(_)));
    }

    #[test]
    fn prevote_certificate_requires_quorum() {
        let (kps, vs) = make_set(4);
        let mut t = tracker();
        // 2/4 = 50 %, pas de quorum.
        t.add_prevote(make_prevote(&kps[0], Some(hash(1))), &vs)
            .unwrap();
        t.add_prevote(make_prevote(&kps[1], Some(hash(1))), &vs)
            .unwrap();
        assert!(t.prevote_certificate(Some(hash(1)), &vs).is_none());

        // 3/4 = 75 % > 2/3, quorum atteint.
        t.add_prevote(make_prevote(&kps[2], Some(hash(1))), &vs)
            .unwrap();
        let cert = t.prevote_certificate(Some(hash(1)), &vs).unwrap();
        assert_eq!(cert.block_hash, Some(hash(1)));
        assert_eq!(cert.prevotes.len(), 3);
    }

    #[test]
    fn prevote_certificate_is_sorted_by_address() {
        let (kps, vs) = make_set(4);
        let mut t = tracker();
        for kp in &kps {
            t.add_prevote(make_prevote(kp, Some(hash(1))), &vs).unwrap();
        }
        let cert = t.prevote_certificate(Some(hash(1)), &vs).unwrap();
        let mut sorted = cert.prevotes.clone();
        sorted.sort_by_key(|e| e.validator_address);
        assert_eq!(cert.prevotes, sorted);
    }

    #[test]
    fn prevote_certificate_for_nil() {
        let (kps, vs) = make_set(4);
        let mut t = tracker();
        for kp in &kps {
            t.add_prevote(make_prevote(kp, None), &vs).unwrap();
        }
        let cert = t.prevote_certificate(None, &vs).unwrap();
        assert_eq!(cert.block_hash, None);
    }

    // --- Precommit ---------------------------------------------------------

    #[test]
    fn add_precommit_ok_and_certificate() {
        let (kps, vs) = make_set(4);
        let mut t = tracker();
        for kp in &kps {
            t.add_precommit(make_precommit(kp, Some(hash(1))), &vs)
                .unwrap();
        }
        let cert = t.commit_certificate(hash(1), &vs).unwrap();
        assert_eq!(cert.block_hash, hash(1));
        assert_eq!(cert.precommits.len(), 4);
    }

    #[test]
    fn add_precommit_double_vote_rejected() {
        let (kps, vs) = make_set(4);
        let mut t = tracker();
        t.add_precommit(make_precommit(&kps[0], Some(hash(1))), &vs)
            .unwrap();
        let err = t
            .add_precommit(make_precommit(&kps[0], Some(hash(2))), &vs)
            .unwrap_err();
        assert!(matches!(err, ConsensusError::DoublePrecommit { .. }));
    }

    #[test]
    fn commit_certificate_requires_quorum() {
        let (kps, vs) = make_set(4);
        let mut t = tracker();
        t.add_precommit(make_precommit(&kps[0], Some(hash(1))), &vs)
            .unwrap();
        assert!(t.commit_certificate(hash(1), &vs).is_none());

        t.add_precommit(make_precommit(&kps[1], Some(hash(1))), &vs)
            .unwrap();
        t.add_precommit(make_precommit(&kps[2], Some(hash(1))), &vs)
            .unwrap();
        assert!(t.commit_certificate(hash(1), &vs).is_some());
    }

    #[test]
    fn prevote_and_precommit_are_independent() {
        let (kps, vs) = make_set(4);
        let mut t = tracker();
        // Prévote pour A, precommit pour B (contradiction logique, mais le
        // tracker les accumule séparément — c'est au driver de faire respecter
        // la cohérence).
        for kp in &kps {
            t.add_prevote(make_prevote(kp, Some(hash(1))), &vs).unwrap();
            t.add_precommit(make_precommit(kp, Some(hash(2))), &vs)
                .unwrap();
        }
        assert!(t.prevote_certificate(Some(hash(1)), &vs).is_some());
        assert!(t.commit_certificate(hash(2), &vs).is_some());
        assert!(t.commit_certificate(hash(1), &vs).is_none());
    }
}
