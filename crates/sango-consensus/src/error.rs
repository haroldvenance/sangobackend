//! Erreurs du crate consensus.

use sango_primitives::{ChainId32, Epoch, Hash32, Height, NativeAddress, Round};
use thiserror::Error;

/// Erreur produite par une opération du consensus.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConsensusError {
    // --- Validator set ------------------------------------------------------
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

    // --- Contexte ------------------------------------------------------------
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

    /// Mauvais `previous_block_hash` sur le header du bloc.
    #[error("parent hash mismatch: expected {expected}, got {got}")]
    ParentHashMismatch {
        /// Attendu.
        expected: Hash32,
        /// Reçu.
        got: Hash32,
    },

    // --- Votes ---------------------------------------------------------------
    /// Un validateur a émis deux prevotes contradictoires.
    ///
    /// Les deux messages **complets** sont fournis, ce qui permet à
    /// l'appelant de construire une `Evidence` pleinement vérifiable.
    #[error("double prevote from {address}")]
    DoublePrevote {
        /// Validateur fautif.
        address: NativeAddress,
        /// Premier message (boxed pour limiter la taille du variant).
        first: Box<sango_types::Prevote>,
        /// Second message, contradictoire.
        second: Box<sango_types::Prevote>,
    },

    /// Un validateur a émis deux precommits contradictoires.
    #[error("double precommit from {address}")]
    DoublePrecommit {
        /// Validateur fautif.
        address: NativeAddress,
        /// Premier message.
        first: Box<sango_types::Precommit>,
        /// Second message, contradictoire.
        second: Box<sango_types::Precommit>,
    },

    // --- Proposer -----------------------------------------------------------
    /// La boucle de rejection sampling n'a pas convergé.
    #[error("proposer sampling exhausted")]
    ProposerSamplingExhausted,

    // --- Proposition --------------------------------------------------------
    /// Version de proposition non supportée.
    #[error("unsupported proposal version: {0}")]
    UnsupportedProposalVersion(u32),

    /// `block_hash` du proposal ne correspond pas au hash calculé du bloc.
    #[error("proposal block_hash mismatch: expected {expected}, got {got}")]
    ProposalBlockHashMismatch {
        /// Hash calculé du bloc.
        expected: Hash32,
        /// Hash annoncé.
        got: Hash32,
    },

    /// Le proposer ne correspond pas à celui sélectionné déterministiquement.
    #[error("wrong proposer: expected {expected}, got {got}")]
    WrongProposer {
        /// Adresse attendue.
        expected: NativeAddress,
        /// Adresse reçue.
        got: NativeAddress,
    },

    /// `valid_round` non strictement inférieur à `round`.
    #[error("invalid valid_round: round={round}, valid_round={valid_round}")]
    InvalidValidRound {
        /// Round courant.
        round: Round,
        /// `valid_round` déclaré.
        valid_round: Round,
    },

    /// `valid_round` non-NIL mais certificat absent.
    #[error("missing valid_round_certificate")]
    MissingValidRoundCertificate,

    /// `valid_round` NIL mais certificat présent.
    #[error("unexpected valid_round_certificate")]
    UnexpectedValidRoundCertificate,

    /// Le certificat PoLC ne porte pas sur le `block_hash` du proposal.
    #[error("PoLC block_hash does not match proposal block_hash")]
    PolcBlockHashMismatch,

    /// Le certificat PoLC n'a pas de quorum.
    #[error("PoLC without quorum: power={power}, total={total}")]
    PolcWithoutQuorum {
        /// Puissance accumulée.
        power: u128,
        /// Puissance totale du set.
        total: u128,
    },

    // --- Machine d'état ------------------------------------------------------
    /// La transition demandée n'est pas permise depuis l'étape courante.
    #[error("invalid step transition: current={current}, expected={expected}")]
    InvalidStep {
        /// Étape courante.
        current: &'static str,
        /// Étape attendue.
        expected: &'static str,
    },

    /// L'appelant n'est pas le proposer attendu pour ce round.
    #[error("not the proposer for this round")]
    NotProposer,

    /// Nous n'avons pas d'identité locale (nœud non-validateur).
    #[error("local validator identity is missing")]
    NoLocalIdentity,

    /// Un déverrouillage a été demandé sans PoLC valide.
    #[error("cannot unlock without a higher-round PoLC on a different block")]
    MissingPolcForUnlock,

    /// Le PoLC fourni pour déverrouiller est antérieur ou égal au lock.
    #[error("PoLC for unlock is not at a higher round: cert_round={cert_round}, locked_round={locked_round}")]
    PolcForUnlockNotHigher {
        /// Round du certificat fourni.
        cert_round: Round,
        /// Round du lock courant.
        locked_round: Round,
    },
}
