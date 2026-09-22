//! Erreurs du crate consensus.

use sango_primitives::{ChainId32, Epoch, Hash32, Height, NativeAddress, Round};
use thiserror::Error;

/// Erreur produite par une opération du consensus.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConsensusError {
    /// Le validator set fourni est vide.
    #[error("empty validator set")]
    EmptyValidatorSet,

    /// Le validator set a une puissance totale nulle.
    #[error("validator set has zero total voting power")]
    ZeroVotingPower,

    /// Deux validateurs partagent la même adresse.
    #[error("duplicate validator address: {0}")]
    DuplicateValidator(NativeAddress),

    /// Un validateur a un voting power nul.
    #[error("validator {0} has zero voting power")]
    ZeroPowerValidator(NativeAddress),

    /// Le validateur n'appartient pas au validator set.
    #[error("unknown validator: {0}")]
    UnknownValidator(NativeAddress),

    /// La signature d'un validateur est invalide.
    #[error("invalid signature from {0}")]
    InvalidSignature(NativeAddress),

    /// Mauvais chain_id.
    #[error("chain_id mismatch: expected {expected}, got {got}")]
    ChainIdMismatch {
        /// Attendu.
        expected: ChainId32,
        /// Reçu.
        got: ChainId32,
    },

    /// Mauvais epoch.
    #[error("epoch mismatch: expected {expected}, got {got}")]
    EpochMismatch {
        /// Attendu.
        expected: Epoch,
        /// Reçu.
        got: Epoch,
    },

    /// Mauvaise hauteur.
    #[error("height mismatch: expected {expected}, got {got}")]
    HeightMismatch {
        /// Attendue.
        expected: Height,
        /// Reçue.
        got: Height,
    },

    /// Mauvais round.
    #[error("round mismatch: expected {expected}, got {got}")]
    RoundMismatch {
        /// Attendu.
        expected: Round,
        /// Reçu.
        got: Round,
    },

    /// Un validateur a émis deux prevotes contradictoires.
    #[error("double prevote from {address}: first {first:?}, second {second:?}")]
    DoublePrevote {
        /// Validateur fautif.
        address: NativeAddress,
        /// Premier `block_hash` (None = NIL).
        first: Option<Hash32>,
        /// Second `block_hash` (None = NIL).
        second: Option<Hash32>,
    },

    /// Un validateur a émis deux precommits contradictoires.
    #[error("double precommit from {address}: first {first:?}, second {second:?}")]
    DoublePrecommit {
        /// Validateur fautif.
        address: NativeAddress,
        /// Premier `block_hash` (None = NIL).
        first: Option<Hash32>,
        /// Second `block_hash` (None = NIL).
        second: Option<Hash32>,
    },

    /// La boucle de rejection sampling pour la sélection du proposer n'a pas
    /// convergé (probabilité ~ 2^-64, ne se produit jamais en pratique).
    #[error("proposer sampling exhausted")]
    ProposerSamplingExhausted,
}
