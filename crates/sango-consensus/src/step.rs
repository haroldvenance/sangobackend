//! Étapes de la machine d'état consensus et actions produites.

use sango_primitives::{Hash32, Height, Round};
use sango_types::{CommitCertificate, Precommit, Prevote, Proposal};

/// Étape courante du consensus à une hauteur/round donnés.
///
/// Freeze section 22 : `PROPOSE → PREVOTE → PRECOMMIT → COMMIT`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum Step {
    /// En attente de la proposition (ou en train de proposer).
    Propose,
    /// Proposition reçue et validée ; en train de voter prevote.
    Prevote,
    /// Quorum prevote observé ; en train de voter precommit.
    Precommit,
    /// Quorum precommit observé ; le bloc est final.
    Commit,
}

impl Step {
    /// Nom pour le debug.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Step::Propose => "propose",
            Step::Prevote => "prevote",
            Step::Precommit => "precommit",
            Step::Commit => "commit",
        }
    }
}

/// Action produite par le [`crate::RoundRunner`].
///
/// Le runner ne fait aucune I/O : il produit des intentions que le driver
/// exécute (signature, broadcast, persistance, application de bloc).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    /// Signer et diffuser cette proposition (nous sommes le proposer).
    ///
    /// `Box` pour limiter la taille de l'enum : `Proposal` contient un
    /// `Block` (potentiellement volumineux).
    BroadcastProposal(Box<Proposal>),
    /// Signer et diffuser cette prevote.
    BroadcastPrevote(Prevote),
    /// Signer et diffuser ce precommit.
    BroadcastPrecommit(Precommit),
    /// Le bloc est final. Le driver doit appliquer le bloc via
    /// `sango-node::apply_block` puis démarrer la hauteur suivante.
    Committed {
        /// Hauteur finalisée.
        height: Height,
        /// Round où le commit a été observé.
        round: Round,
        /// Hash du bloc finalisé.
        block_hash: Hash32,
        /// Certificat de commit (>2/3 precommits).
        certificate: CommitCertificate,
    },
    /// Démarrer un nouveau round à la même hauteur.
    ///
    /// Le driver doit créer un nouveau [`crate::RoundRunner`] pour le round
    /// demandé en préservant le `ConsensusState` (locks).
    StartRound(Round),
}
