//! Machine d'état consensus pour un `(height, round)` donné.
//!
//! ## Rôle
//!
//! Le [`RoundRunner`] est une machine d'état **pure** : il reçoit des
//! événements (propositions, votes, timeouts) et produit des [`Action`]s
//! (broadcasts, transitions, commit). Il ne fait **aucune I/O** : c'est le
//! driver qui exécute les actions.
//!
//! ## Cycle de vie
//!
//! ```text
//! new()          ─►  Step::Propose
//!                     │
//!    propose() ──────┤  (si nous sommes le proposer)
//!    on_proposal() ──┘
//!                     ▼
//!                    Step::Prevote
//!                     │
//!    on_prevote() ───┤  (quorum observé)
//!    on_timeout_prevote()
//!                     ▼
//!                    Step::Precommit
//!                     │
//!    on_precommit() ─┤  (quorum observé)
//!    on_timeout_precommit()
//!                     ▼
//!                    Step::Commit
//! ```
//!
//! Le driver instancie un nouveau `RoundRunner` à chaque round, en
//! clonant le `ConsensusState` final du round précédent (locks préservés).

use sango_crypto::NativeKeypair;
use sango_primitives::{ChainId32, Epoch, Hash32, Height, NativeAddress, PublicKey, Round};
use sango_types::{Block, CommitCertificate, Precommit, Prevote, Proposal};

use crate::error::ConsensusError;
use crate::proposal_verify::{verify_proposal, ProposalContext};
use crate::proposer::select_proposer;
use crate::state::{ConsensusState, PolcOutcome};
use crate::step::{Action, Step};
use crate::validator_set::ValidatorSet;
use crate::vote_tracker::VoteTracker;

/// Contexte fixe d'un round.
#[derive(Clone, Copy, Debug)]
pub struct RoundContext {
    /// Chain ID natif.
    pub chain_id: ChainId32,
    /// Epoch courant.
    pub epoch: Epoch,
    /// Hauteur courante.
    pub height: Height,
    /// Round courant.
    pub round: Round,
    /// Hash du bloc parent (fin du round précédent).
    pub parent_hash: Hash32,
}

impl RoundContext {
    /// Construit le contexte attendu pour la vérification d'une proposal.
    #[must_use]
    pub fn proposal_context(&self) -> ProposalContext {
        ProposalContext {
            chain_id: self.chain_id,
            epoch: self.epoch,
            height: self.height,
            round: self.round,
            parent_hash: self.parent_hash,
        }
    }
}

/// Identité locale d'un validateur.
///
/// Contient le keypair nécessaire pour signer. Dans un futur raffinement,
/// ceci pourra être remplacé par un trait `Signer` (HSM, wallet externe).
pub struct LocalIdentity {
    keypair: NativeKeypair,
}

impl LocalIdentity {
    /// Crée une identité locale à partir d'un keypair.
    #[must_use]
    pub fn new(keypair: NativeKeypair) -> Self {
        Self { keypair }
    }

    /// Adresse native dérivée de la clé publique.
    #[must_use]
    pub fn address(&self) -> NativeAddress {
        sango_crypto::derive_native_address(&self.keypair.public_key())
    }

    /// Clé publique.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.keypair.public_key()
    }

    /// Référence sur le keypair sous-jacent.
    #[must_use]
    pub fn keypair(&self) -> &NativeKeypair {
        &self.keypair
    }
}

impl std::fmt::Debug for LocalIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalIdentity")
            .field("address", &self.address())
            .finish_non_exhaustive()
    }
}

/// Machine d'état consensus pour un `(height, round)`.
pub struct RoundRunner {
    ctx: RoundContext,
    validator_set: ValidatorSet,
    state: ConsensusState,
    tracker: VoteTracker,
    step: Step,
    local: Option<LocalIdentity>,
    current_proposal: Option<Proposal>,
    actions: Vec<Action>,
    already_prevoted: bool,
    already_precommitted: bool,
    committed: bool,
}

impl RoundRunner {
    /// Crée un runner pour un round.
    ///
    /// Le `ConsensusState` fourni doit être à la bonne hauteur ; le runner
    /// le clonera et mettra à jour son `round` interne via
    /// [`ConsensusState::set_round`].
    #[must_use]
    pub fn new(
        ctx: RoundContext,
        validator_set: ValidatorSet,
        mut state: ConsensusState,
        local: Option<LocalIdentity>,
    ) -> Self {
        state.set_round(ctx.round);
        let tracker = VoteTracker::new(ctx.chain_id, ctx.epoch, ctx.height, ctx.round);
        Self {
            ctx,
            validator_set,
            state,
            tracker,
            step: Step::Propose,
            local,
            current_proposal: None,
            actions: Vec::new(),
            already_prevoted: false,
            already_precommitted: false,
            committed: false,
        }
    }

    // --- Accesseurs ---------------------------------------------------------

    /// Étape courante.
    #[must_use]
    pub fn step(&self) -> Step {
        self.step
    }

    /// Contexte du round.
    #[must_use]
    pub fn ctx(&self) -> &RoundContext {
        &self.ctx
    }

    /// État consensus sous-jacent.
    #[must_use]
    pub fn state(&self) -> &ConsensusState {
        &self.state
    }

    /// Vrai si un commit a été émis.
    #[must_use]
    pub fn is_committed(&self) -> bool {
        self.committed
    }

    /// Consomme le runner et retourne le `ConsensusState` final.
    ///
    /// Le driver l'utilise pour créer le runner du round suivant.
    #[must_use]
    pub fn into_state(self) -> ConsensusState {
        self.state
    }

    /// Proposer attendu pour ce round.
    pub fn expected_proposer(&self) -> Result<NativeAddress, ConsensusError> {
        select_proposer(
            &self.ctx.chain_id,
            self.ctx.epoch,
            self.ctx.height,
            self.ctx.round,
            &self.ctx.parent_hash,
            &self.validator_set,
        )
    }

    /// Vrai si l'identité locale est le proposer attendu.
    pub fn is_proposer(&self) -> Result<bool, ConsensusError> {
        match &self.local {
            None => Ok(false),
            Some(id) => Ok(id.address() == self.expected_proposer()?),
        }
    }

    /// Récupère et vide les actions accumulées.
    pub fn drain_actions(&mut self) -> Vec<Action> {
        std::mem::take(&mut self.actions)
    }

    // --- Proposer -----------------------------------------------------------

    /// Produit la proposition pour ce round (nous sommes le proposer).
    ///
    /// Émet `Action::BroadcastProposal` et s'auto-applique `on_proposal`.
    ///
    /// # Erreurs
    ///
    /// - [`ConsensusError::NotProposer`] si nous ne sommes pas le proposer
    ///   attendu.
    /// - [`ConsensusError::InvalidStep`] si nous ne sommes plus à l'étape
    ///   `Propose`.
    pub fn propose(&mut self, block: Block) -> Result<(), ConsensusError> {
        if self.step != Step::Propose {
            return Err(ConsensusError::InvalidStep {
                current: self.step.name(),
                expected: "propose",
            });
        }
        if self.current_proposal.is_some() {
            // Une proposition a déjà été observée.
            return Ok(());
        }

        let id = self.local.as_ref().ok_or(ConsensusError::NoLocalIdentity)?;
        let expected = self.expected_proposer()?;
        if id.address() != expected {
            return Err(ConsensusError::NotProposer);
        }

        // Le header doit avoir le proposer courant.
        let mut block = block;
        block.header.proposer_address = id.address();
        let block_hash = block.hash();

        let unsigned = Proposal {
            version: sango_types::PROTOCOL_VERSION_V1,
            chain_id: self.ctx.chain_id,
            epoch: self.ctx.epoch,
            height: self.ctx.height,
            round: self.ctx.round,
            block,
            block_hash,
            valid_round: None,
            valid_round_certificate: None,
            proposer_address: id.address(),
            proposer_signature: sango_primitives::Signature::ZERO,
        };
        let proposal = unsigned.sign(id.keypair());

        self.actions
            .push(Action::BroadcastProposal(Box::new(proposal.clone())));
        // Loopback : on traite notre propre proposition comme si on venait
        // de la recevoir du réseau.
        self.on_proposal(proposal)
    }

    // --- Événements entrants ------------------------------------------------

    /// Traite une proposition reçue.
    ///
    /// ## Comportement
    ///
    /// - Si `step != Propose` ou si une proposition a déjà été traitée,
    ///   ignore silencieusement (retourne `Ok`).
    /// - Vérifie la proposition ; si invalide, retourne une erreur sans
    ///   transition.
    /// - Si `valid_round` est fourni, applique `observe_polc` (déverrouillage
    ///   éventuel).
    /// - Transition vers `Prevote`, calcule la cible
    ///   ([`ConsensusState::decide_prevote`]), signe et émet
    ///   `Action::BroadcastPrevote` si nous sommes validateur.
    pub fn on_proposal(&mut self, proposal: Proposal) -> Result<(), ConsensusError> {
        if self.step != Step::Propose || self.current_proposal.is_some() {
            return Ok(());
        }

        verify_proposal(&proposal, &self.ctx.proposal_context(), &self.validator_set)?;

        // Déverrouillage éventuel via PoLC.
        if let (Some(vr), Some(_cert)) = (
            proposal.valid_round,
            proposal.valid_round_certificate.as_ref(),
        ) {
            let _ = self.state.observe_polc(proposal.block_hash, vr);
        }

        let proposed_block_hash = proposal.block_hash;
        self.current_proposal = Some(proposal);
        self.step = Step::Prevote;

        // Vote local.
        let target = self.state.decide_prevote(Some(proposed_block_hash));
        self.cast_prevote(target)?;
        self.check_prevote_quorum()?;
        Ok(())
    }

    /// Traite un prevote reçu.
    pub fn on_prevote(&mut self, prevote: Prevote) -> Result<(), ConsensusError> {
        if self.committed {
            return Ok(());
        }
        self.tracker.add_prevote(prevote, &self.validator_set)?;
        self.check_prevote_quorum()
    }

    /// Traite un precommit reçu.
    pub fn on_precommit(&mut self, precommit: Precommit) -> Result<(), ConsensusError> {
        if self.committed {
            return Ok(());
        }
        self.tracker.add_precommit(precommit, &self.validator_set)?;
        self.check_precommit_quorum()
    }

    // --- Timeouts -----------------------------------------------------------

    /// Timeout de l'étape `Propose`.
    ///
    /// Si aucune proposition n'a été observée, prevote NIL.
    pub fn on_timeout_propose(&mut self) -> Result<(), ConsensusError> {
        if self.step != Step::Propose {
            return Ok(());
        }
        self.step = Step::Prevote;
        self.cast_prevote(None)?;
        self.check_prevote_quorum()?;
        Ok(())
    }

    /// Timeout de l'étape `Prevote`.
    ///
    /// Precommit NIL si l'on n'est pas déjà en `Precommit`/`Commit`.
    pub fn on_timeout_prevote(&mut self) -> Result<(), ConsensusError> {
        if self.step != Step::Prevote {
            return Ok(());
        }
        self.step = Step::Precommit;
        self.cast_precommit(None)?;
        self.check_precommit_quorum()?;
        Ok(())
    }

    /// Timeout de l'étape `Precommit`.
    ///
    /// Si aucun commit n'a été observé, émet `Action::StartRound(round+1)`.
    pub fn on_timeout_precommit(&mut self) -> Result<(), ConsensusError> {
        if self.step != Step::Precommit || self.committed {
            return Ok(());
        }
        let next = Round::new(self.ctx.round.get().saturating_add(1));
        self.actions.push(Action::StartRound(next));
        Ok(())
    }

    // --- Mécanique interne --------------------------------------------------

    /// Signe et émet un prevote pour `target`, et l'ajoute au tracker.
    fn cast_prevote(&mut self, target: Option<Hash32>) -> Result<(), ConsensusError> {
        if self.already_prevoted {
            return Ok(());
        }
        self.already_prevoted = true;

        let Some(id) = &self.local else {
            return Ok(());
        };

        let unsigned = Prevote {
            chain_id: self.ctx.chain_id,
            epoch: self.ctx.epoch,
            height: self.ctx.height,
            round: self.ctx.round,
            block_hash: target,
            validator_address: id.address(),
            validator_signature: sango_primitives::Signature::ZERO,
        };
        let signed = unsigned.sign(id.keypair());
        self.actions.push(Action::BroadcastPrevote(signed));
        self.tracker.add_prevote(signed, &self.validator_set)?;
        Ok(())
    }

    /// Signe et émet un precommit pour `target`, et l'ajoute au tracker.
    fn cast_precommit(&mut self, target: Option<Hash32>) -> Result<(), ConsensusError> {
        if self.already_precommitted {
            return Ok(());
        }
        self.already_precommitted = true;

        let Some(id) = &self.local else {
            return Ok(());
        };

        let unsigned = Precommit {
            chain_id: self.ctx.chain_id,
            epoch: self.ctx.epoch,
            height: self.ctx.height,
            round: self.ctx.round,
            block_hash: target,
            validator_address: id.address(),
            validator_signature: sango_primitives::Signature::ZERO,
        };
        let signed = unsigned.sign(id.keypair());
        self.actions.push(Action::BroadcastPrecommit(signed));
        self.tracker.add_precommit(signed, &self.validator_set)?;
        Ok(())
    }

    /// Vérifie si un quorum prevote est atteint pour un bloc (ou NIL) ; si
    /// oui, déclenche la transition `Prevote → Precommit`.
    fn check_prevote_quorum(&mut self) -> Result<(), ConsensusError> {
        if self.step != Step::Prevote {
            return Ok(());
        }

        // Chercher un bloc (ou NIL) qui atteint le quorum.
        // Note : le seul `block_hash` possible qui puisse atteindre le
        // quorum est unique par round (double-vote impossible >2/3).
        let candidates: Vec<Option<Hash32>> = if let Some(p) = &self.current_proposal {
            vec![Some(p.block_hash), None]
        } else {
            vec![None]
        };

        for candidate in candidates {
            if let Some(cert) = self
                .tracker
                .prevote_certificate(candidate, &self.validator_set)
            {
                // Observer le PoLC (peut déverrouiller).
                if let Some(bh) = candidate {
                    match self.state.observe_polc(bh, self.ctx.round) {
                        PolcOutcome::Locked
                        | PolcOutcome::Upgraded
                        | PolcOutcome::UnlockedAndLocked
                        | PolcOutcome::Ignored => {}
                    }
                    // Note : on ignore le résultat, l'effet est déjà appliqué.
                }
                let _ = cert;

                // Transition vers Precommit.
                self.step = Step::Precommit;
                // Cible : le bloc valid si on en a un, sinon NIL.
                let target = match self.state.valid() {
                    Some((bh, _)) if candidate == Some(bh) => Some(bh),
                    _ => None,
                };
                self.cast_precommit(target)?;
                return self.check_precommit_quorum();
            }
        }
        Ok(())
    }

    /// Vérifie si un quorum precommit est atteint pour un bloc ; si oui,
    /// émet `Action::Committed`.
    fn check_precommit_quorum(&mut self) -> Result<(), ConsensusError> {
        if self.committed || self.step == Step::Precommit {
            // On peut être appelé depuis `Precommit` ou `Commit`.
        }

        // On cherche un `block_hash` non-NIL qui a le quorum.
        let Some(proposal) = &self.current_proposal else {
            return Ok(());
        };
        let bh = proposal.block_hash;

        if let Some(cert) = self.tracker.commit_certificate(bh, &self.validator_set) {
            self.step = Step::Commit;
            self.committed = true;
            self.actions.push(Action::Committed {
                height: self.ctx.height,
                round: self.ctx.round,
                block_hash: bh,
                certificate: cert,
            });
        }
        Ok(())
    }
}

impl std::fmt::Debug for RoundRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoundRunner")
            .field("ctx", &self.ctx)
            .field("step", &self.step)
            .field("state", &self.state)
            .field("local", &self.local)
            .field("has_proposal", &self.current_proposal.is_some())
            .field("committed", &self.committed)
            .finish_non_exhaustive()
    }
}

// Silence clippy sur une méthode publique non utilisée en interne.
#[allow(dead_code)]
fn _unused_cert(_: &CommitCertificate) {}
