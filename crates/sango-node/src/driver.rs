//! Driver événementiel pour la participation au consensus.

use std::collections::{HashMap, HashSet};

use sango_consensus::{
    Action, ConsensusError, ConsensusState, LocalIdentity, RoundContext, RoundRunner, Step,
    ValidatorSet,
};
use sango_primitives::{Epoch, Hash32, Height, NativeAddress, Round};
use sango_types::{CommitCertificate, Precommit, Prevote, Proposal, Transaction};

use crate::base_fee::INITIAL_BASE_FEE;
use crate::error::NodeError;
use crate::node_handle::NodeHandle;

/// Nombre maximum de transactions incluses dans un bloc proposé.
pub const MAX_TXS_PER_BLOCK: usize = 1024;

/// Nombre maximal d'itérations dans `process_actions`.
const MAX_ACTION_LOOPS: usize = 32;

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

/// Driver consensus pour un nœud.
pub struct Driver {
    handle: NodeHandle,
    validator_set: ValidatorSet,
    local: Option<LocalIdentity>,
    epoch: Epoch,
    runner: RoundRunner,
    outbox: Vec<OutgoingMessage>,
    events: Vec<DriverEvent>,
}

impl Driver {
    /// Construit un driver à partir d'un `NodeHandle`.
    pub fn new(
        handle: NodeHandle,
        validator_set: ValidatorSet,
        local: Option<LocalIdentity>,
        epoch: Epoch,
    ) -> Result<Self, DriverError> {
        let (chain_id, height, parent_hash) = handle.with_node(|n| {
            let (h, p) = match n.tip() {
                Some(t) => (Height::new(t.height.get() + 1), t.block_hash),
                None => (Height::new(0), Hash32::ZERO),
            };
            (n.chain_id(), h, p)
        });
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
            handle,
            validator_set,
            local,
            epoch,
            runner,
            outbox: Vec::new(),
            events: Vec::new(),
        })
    }

    // --- Accesseurs --------------------------------------------------------

    /// Handle partagé sur le nœud + mempool.
    #[must_use]
    pub fn node_handle(&self) -> &NodeHandle {
        &self.handle
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

    /// Propose un bloc (avec txs du mempool) si nous sommes le proposer.
    pub fn maybe_propose(&mut self) -> Result<(), DriverError> {
        if self.runner.step() != Step::Propose {
            return Ok(());
        }
        if !self.runner.is_proposer()? {
            return Ok(());
        }

        let id = self.local.as_ref().ok_or(DriverError::NoLocalIdentity)?;
        let proposer = id.address();

        // 1. Récupérer les candidats du mempool, ordonnés par priorité.
        let candidates = self.collect_mempool_candidates();

        // 2. Construire le bloc via Node (pré-validation + application trial).
        let epoch = self.epoch;
        let round = self.runner.ctx().round;
        let height = self.runner.ctx().height;
        let timestamp = 1_700_000_000u64.saturating_add(height.get());
        let (block, _validated) = self.handle.with_node(|n| {
            n.prepare_block_from_candidates(
                epoch,
                round,
                candidates,
                MAX_TXS_PER_BLOCK,
                proposer,
                timestamp,
            )
        });

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

    /// Collecte les transactions candidates du mempool, ordonnées par
    /// priorité effective décroissante et FIFO.
    ///
    /// Le tri respecte les dépendances de nonce via
    /// [`sango_mempool::Mempool::select_for_block`].
    fn collect_mempool_candidates(&self) -> Vec<Transaction> {
        // 1. Sendors uniques présents dans le mempool.
        let senders: Vec<NativeAddress> = self.handle.with_mempool(|pool| {
            let mut s = HashSet::new();
            for h in pool.hashes() {
                if let Some(e) = pool.get(&h) {
                    s.insert(e.tx.sender);
                }
            }
            s.into_iter().collect()
        });

        if senders.is_empty() {
            return Vec::new();
        }

        // 2. Nonces courants dans l'état.
        let nonces: HashMap<NativeAddress, u64> = self.handle.with_node(|n| {
            senders
                .iter()
                .map(|s| (*s, n.state().nonce_of(s)))
                .collect()
        });

        // 3. Sélection ordonnée.
        let entries = self
            .handle
            .with_mempool(|pool| pool.select_for_block(MAX_TXS_PER_BLOCK, &nonces));

        entries.into_iter().map(|e| e.tx).collect()
    }

    /// Purge le mempool après l'application d'un bloc.
    ///
    /// - retire les transactions dont le nonce est déjà appliqué ;
    /// - retire celles dont `max_fee < new_base_fee`.
    fn prune_mempool(&self) {
        // 1. Sendors uniques encore dans le mempool.
        let senders: Vec<NativeAddress> = self.handle.with_mempool(|pool| {
            let mut s = HashSet::new();
            for h in pool.hashes() {
                if let Some(e) = pool.get(&h) {
                    s.insert(e.tx.sender);
                }
            }
            s.into_iter().collect()
        });

        // 2. Nonces courants + nouvelle base fee (state read lock).
        let (nonces, new_base_fee) = self.handle.with_node(|n| {
            let nonces: HashMap<NativeAddress, u64> = senders
                .iter()
                .map(|s| (*s, n.state().nonce_of(s)))
                .collect();
            let bf = n.expected_base_fee().unwrap_or(INITIAL_BASE_FEE);
            (nonces, bf)
        });

        // 3. Prune + evict (mempool lock).
        self.handle.with_mempool(|pool| {
            let _ = pool.prune_below_nonces(&nonces);
            let _ = pool.evict_below_base_fee(new_base_fee);
        });
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
                        self.handle.with_node_mut(|n| n.apply_block(&block))?;
                        self.prune_mempool();
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
