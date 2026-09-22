//! Driver événementiel pour la participation au consensus.

use sango_consensus::{
    Action, ConsensusError, ConsensusState, LocalIdentity, RoundContext, RoundRunner, Step,
    ValidatorSet,
};
use sango_primitives::{Epoch, Hash32, Height, NativeAddress, Round};
use sango_types::{Block, BlockHeader, CommitCertificate, Precommit, Prevote, Proposal};

use crate::error::NodeError;
use crate::node::Node;

/// Message réseau sortant produit par le driver.
#[derive(Clone, Debug)]
pub enum OutgoingMessage {
    /// Proposition de bloc.
    Proposal(Box<Proposal>),
    /// Vote prevote.
    Prevote(Prevote),
    /// Vote precommit.
    Precommit(Precommit),
}

/// Événement produit par le driver, à destination de l'appelant.
#[derive(Clone, Debug)]
pub enum DriverEvent {
    /// Un bloc a été finalisé et appliqué.
    Committed {
        /// Hauteur finalisée.
        height: Height,
        /// Round où le commit a eu lieu.
        round: Round,
        /// Hash du bloc.
        block_hash: Hash32,
        /// Certificat de commit.
        certificate: CommitCertificate,
    },
    /// Un nouveau round a démarré à la même hauteur.
    RoundAdvanced(Round),
}

/// Erreur produite par le driver.
#[derive(Debug, thiserror::Error)]
pub enum DriverError {
    /// Erreur du nœud sous-jacent.
    #[error("node: {0}")]
    Node(#[from] NodeError),

    /// Erreur du consensus.
    #[error("consensus: {0}")]
    Consensus(#[from] ConsensusError),

    /// Aucune identité locale (nœud non-validateur).
    #[error("no local identity")]
    NoLocalIdentity,

    /// Bloc manquant au moment du commit.
    #[error("current proposal is missing at commit time")]
    MissingBlockForCommit,

    /// Le driver a généré trop d'actions en cascade.
    #[error("driver action loop exceeded limit")]
    TooManyActions,
}

/// Nombre maximal d'itérations dans `process_actions`.
const MAX_ACTION_LOOPS: usize = 32;

/// Driver consensus pour un nœud.
pub struct Driver {
    node: Node,
    validator_set: ValidatorSet,
    local: Option<LocalIdentity>,
    epoch: Epoch,
    runner: RoundRunner,
    outbox: Vec<OutgoingMessage>,
    events: Vec<DriverEvent>,
}

impl Driver {
    /// Construit un driver à partir d'un nœud existant.
    pub fn new(
        node: Node,
        validator_set: ValidatorSet,
        local: Option<LocalIdentity>,
        epoch: Epoch,
    ) -> Result<Self, DriverError> {
        let chain_id = node.chain_id();
        let (height, parent_hash) = match node.tip() {
            Some(t) => (Height::new(t.height.get() + 1), t.block_hash),
            None => (Height::new(0), Hash32::ZERO),
        };
        let round = Round::new(0);
        let ctx = RoundContext {
            chain_id,
            epoch,
            height,
            round,
            parent_hash,
        };
        let state = ConsensusState::new(height);
        let runner = RoundRunner::new(ctx, validator_set.clone(), state, local.clone());
        Ok(Self {
            node,
            validator_set,
            local,
            epoch,
            runner,
            outbox: Vec::new(),
            events: Vec::new(),
        })
    }

    // --- Accesseurs --------------------------------------------------------

    /// Nœud sous-jacent (lecture).
    #[must_use]
    pub fn node(&self) -> &Node {
        &self.node
    }

    /// Validator set.
    #[must_use]
    pub fn validator_set(&self) -> &ValidatorSet {
        &self.validator_set
    }

    /// Hauteur courante.
    #[must_use]
    pub fn current_height(&self) -> Height {
        self.runner.ctx().height
    }

    /// Round courant.
    #[must_use]
    pub fn current_round(&self) -> Round {
        self.runner.ctx().round
    }

    /// Étape courante.
    #[must_use]
    pub fn current_step(&self) -> Step {
        self.runner.step()
    }

    /// Adresse locale (None si non-validateur).
    #[must_use]
    pub fn local_address(&self) -> Option<NativeAddress> {
        self.local.as_ref().map(LocalIdentity::address)
    }

    /// Vrai si nous sommes le proposer attendu.
    pub fn is_proposer(&self) -> Result<bool, DriverError> {
        Ok(self.runner.is_proposer()?)
    }

    // --- API principale ----------------------------------------------------

    /// Propose un bloc si nous sommes le proposer et à l'étape `Propose`.
    pub fn maybe_propose(&mut self) -> Result<(), DriverError> {
        if self.runner.step() != Step::Propose {
            return Ok(());
        }
        if !self.runner.is_proposer()? {
            return Ok(());
        }
        let block = self.build_block()?;
        self.runner.propose(block)?;
        self.process_actions()
    }

    /// Traite une proposition reçue du réseau.
    pub fn handle_proposal(&mut self, p: Proposal) -> Result<(), DriverError> {
        match self.runner.on_proposal(p) {
            Ok(()) => self.process_actions(),
            Err(e) if is_stale(&e) => Ok(()),
            Err(e) => Err(DriverError::Consensus(e)),
        }
    }

    /// Traite une prevote reçue du réseau.
    pub fn handle_prevote(&mut self, v: Prevote) -> Result<(), DriverError> {
        match self.runner.on_prevote(v) {
            Ok(()) => self.process_actions(),
            Err(e) if is_stale(&e) => Ok(()),
            Err(e) => Err(DriverError::Consensus(e)),
        }
    }

    /// Traite un precommit reçu du réseau.
    pub fn handle_precommit(&mut self, c: Precommit) -> Result<(), DriverError> {
        match self.runner.on_precommit(c) {
            Ok(()) => self.process_actions(),
            Err(e) if is_stale(&e) => Ok(()),
            Err(e) => Err(DriverError::Consensus(e)),
        }
    }

    /// Traite un timeout pour l'étape courante.
    pub fn handle_timeout(&mut self) -> Result<(), DriverError> {
        match self.runner.step() {
            Step::Propose => self.runner.on_timeout_propose()?,
            Step::Prevote => self.runner.on_timeout_prevote()?,
            Step::Precommit => self.runner.on_timeout_precommit()?,
            Step::Commit => return Ok(()),
        }
        self.process_actions()
    }

    /// Récupère et vide les messages sortants.
    pub fn drain_outbox(&mut self) -> Vec<OutgoingMessage> {
        std::mem::take(&mut self.outbox)
    }

    /// Récupère et vide les événements.
    pub fn drain_events(&mut self) -> Vec<DriverEvent> {
        std::mem::take(&mut self.events)
    }

    // --- Internes ----------------------------------------------------------

    fn build_block(&self) -> Result<Block, DriverError> {
        let id = self.local.as_ref().ok_or(DriverError::NoLocalIdentity)?;
        let (height, parent_hash) = match self.node.tip() {
            Some(t) => (t.height.get() + 1, t.block_hash),
            None => (0, Hash32::ZERO),
        };
        let base_fee = self.node.expected_base_fee()?;
        let block = Block {
            header: BlockHeader {
                version: sango_types::PROTOCOL_VERSION_V1,
                chain_id: self.node.chain_id(),
                epoch: self.epoch,
                height: Height::new(height),
                round: self.runner.ctx().round,
                previous_block_hash: parent_hash,
                timestamp: 1_700_000_000 + height,
                proposer_address: id.address(),
                transaction_root: Hash32::ZERO,
                state_root: Hash32::ZERO,
                receipt_root: Hash32::ZERO,
                gas_used: 0,
                gas_limit: 30_000_000,
                base_fee,
            },
            transactions: Vec::new(),
        };
        Ok(block)
    }

    fn process_actions(&mut self) -> Result<(), DriverError> {
        for _ in 0..MAX_ACTION_LOOPS {
            let actions = self.runner.drain_actions();
            if actions.is_empty() {
                return Ok(());
            }
            for action in actions {
                match action {
                    Action::BroadcastProposal(p) => {
                        self.outbox.push(OutgoingMessage::Proposal(p));
                    }
                    Action::BroadcastPrevote(v) => {
                        self.outbox.push(OutgoingMessage::Prevote(v));
                    }
                    Action::BroadcastPrecommit(c) => {
                        self.outbox.push(OutgoingMessage::Precommit(c));
                    }
                    Action::Committed {
                        height,
                        round,
                        block_hash,
                        certificate,
                    } => {
                        let block = self
                            .runner
                            .current_proposal()
                            .map(|p| p.block.clone())
                            .ok_or(DriverError::MissingBlockForCommit)?;
                        self.node.apply_block(&block)?;
                        self.events.push(DriverEvent::Committed {
                            height,
                            round,
                            block_hash,
                            certificate,
                        });
                        let next_height = Height::new(height.get() + 1);
                        self.runner
                            .reset_for_round(next_height, Round::new(0), block_hash);
                    }
                    Action::StartRound(new_round) => {
                        self.events.push(DriverEvent::RoundAdvanced(new_round));
                        let height = self.runner.ctx().height;
                        let parent_hash = self.runner.ctx().parent_hash;
                        self.runner.reset_for_round(height, new_round, parent_hash);
                    }
                }
            }
        }
        Err(DriverError::TooManyActions)
    }
}

fn is_stale(e: &ConsensusError) -> bool {
    matches!(
        e,
        ConsensusError::HeightMismatch { .. }
            | ConsensusError::RoundMismatch { .. }
            | ConsensusError::EpochMismatch { .. }
            | ConsensusError::ChainIdMismatch { .. }
    )
}

impl std::fmt::Debug for Driver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Driver")
            .field("height", &self.current_height())
            .field("round", &self.current_round())
            .field("step", &self.current_step())
            .field("local", &self.local_address())
            .finish_non_exhaustive()
    }
}
