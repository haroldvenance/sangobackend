//! Driver événementiel pour la participation au consensus.
//!
//! Le driver relie la machine d'état [`RoundRunner`] (pure) au monde
//! extérieur : il exécute les [`Action`]s (broadcast P2P, application de
//! bloc, persistance) et achemine les événements réseau vers le runner.
//!
//! ## Buffer de messages futurs
//!
//! Un pair peut commiter la hauteur `h` avant nous et diffuser la
//! proposition `h+1` pendant qu'on termine `h`. Sans buffer, on jetterait
//! ce message ([`is_stale`]) et on ne voterait jamais pour `h+1` — le
//! consensus se bloquerait. Les messages reçus à une hauteur strictement
//! supérieure à la hauteur courante sont donc mis de côté et réinjectés
//! après chaque `reset_for_round` (voir `drain_buffered_for_current_height`).

use std::collections::{HashMap, HashSet};

use sango_consensus::{
    Action, ConsensusError, ConsensusState, LocalIdentity, RoundContext, RoundRunner, Step,
    ValidatorSet,
};
use sango_p2p::{NetworkMessage, P2pEvent, P2pService};
use sango_primitives::{Epoch, Hash32, Height, NativeAddress, Round};
use sango_types::{
    CommitCertificate, ConsensusMessage, ConsensusMessageType, Evidence, EvidenceType, Precommit,
    Prevote, Proposal, Transaction,
};

use crate::base_fee::INITIAL_BASE_FEE;
use crate::error::NodeError;
use crate::node_handle::NodeHandle;

/// Nombre maximum de transactions incluses dans un bloc proposé.
pub const MAX_TXS_PER_BLOCK: usize = 1024;

/// Nombre maximal d'itérations dans `process_actions`.
const MAX_ACTION_LOOPS: usize = 32;

/// Borne du buffer de messages futurs (anti-DoS mémoire).
///
/// Au-delà, les messages excédentaires sont silencieusement jetés : un
/// pair malveillant ne peut pas saturer la mémoire du nœud.
const MAX_BUFFERED_PER_KIND: usize = 1024;

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
    /// Evidences détectées en attente d'inclusion dans un prochain bloc.
    pending_evidences: Vec<Evidence>,
    /// Service P2P (optionnel). Si `None`, le driver fonctionne en mode
    /// autonome (self-loopback pur, utile pour les tests).
    p2p: Option<P2pService>,

    // --- Buffer des messages reçus à une hauteur future ---
    //
    // Un pair peut commit h avant nous et diffuser h+1 pendant qu'on
    // termine h. Sans ce buffer, on jette le message et on ne vote
    // jamais pour h+1 — le consensus se bloque.
    buffered_proposals: Vec<Proposal>,
    buffered_prevotes: Vec<Prevote>,
    buffered_precommits: Vec<Precommit>,
}

impl Driver {
    /// Construit un driver à partir d'un `NodeHandle`.
    ///
    /// La hauteur initiale est `tip.height + 1` (ou `0` si aucun tip) :
    /// le driver propose le **prochain** bloc, pas celui déjà appliqué.
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
            pending_evidences: Vec::new(),
            p2p: None,
            buffered_proposals: Vec::new(),
            buffered_prevotes: Vec::new(),
            buffered_precommits: Vec::new(),
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

    /// Hauteur courante (celle du prochain bloc à proposer).
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

    /// Nombre d'evidences en attente d'inclusion.
    #[must_use]
    pub fn pending_evidence_count(&self) -> usize {
        self.pending_evidences.len()
    }

    // --- P2P ---------------------------------------------------------------

    /// Attache un service P2P au driver.
    ///
    /// Une fois attaché, les messages sortants sont publiés sur le réseau
    /// **en plus** d'être poussés dans `outbox` (self-loopback local), et
    /// `drain_p2p_events()` doit être appelé régulièrement pour consommer
    /// les messages entrants.
    ///
    /// Peut être appelé plusieurs fois ; le service précédent est remplacé.
    pub fn attach_p2p(&mut self, svc: P2pService) {
        self.p2p = Some(svc);
    }

    /// Vrai si un service P2P est attaché.
    #[must_use]
    pub fn has_p2p(&self) -> bool {
        self.p2p.is_some()
    }

    /// Poll et route les événements P2P entrants.
    ///
    /// Consomme au plus `max_events` événements. Retourne le nombre
    /// d'événements traités.
    pub fn drain_p2p_events(&mut self, max_events: usize) -> Result<usize, DriverError> {
        let Some(p2p) = self.p2p.clone() else {
            return Ok(0);
        };

        let mut count = 0;
        while count < max_events {
            let Some(event) = p2p.try_recv_event() else {
                break;
            };
            count += 1;
            match event {
                P2pEvent::Message { message, .. } => match *message {
                    NetworkMessage::Proposal(p) => {
                        let _ = self.handle_proposal(*p);
                    }
                    NetworkMessage::Prevote(v) => {
                        let _ = self.handle_prevote(v);
                    }
                    NetworkMessage::Precommit(c) => {
                        let _ = self.handle_precommit(c);
                    }
                    NetworkMessage::Transaction(_) | NetworkMessage::Block(_) => {}
                },
                P2pEvent::PeerConnected(peer) => {
                    eprintln!("[p2p] peer connecté: {peer}");
                }
                P2pEvent::PeerDisconnected(peer) => {
                    eprintln!("[p2p] peer déconnecté: {peer}");
                }
                P2pEvent::TransportError(msg) => {
                    eprintln!("[p2p] erreur transport: {msg}");
                }
                P2pEvent::NewListenAddr(addr) => {
                    eprintln!("[p2p] listen on {addr}");
                }
                P2pEvent::Subscribed { peer_id, topic } => {
                    eprintln!("[p2p] {peer_id} subscribed to {topic}");
                }
            }
        }
        Ok(count)
    }

    // --- API principale ----------------------------------------------------

    /// Propose un bloc (avec txs du mempool + evidences) si nous sommes
    /// le proposer.
    pub fn maybe_propose(&mut self) -> Result<(), DriverError> {
        if self.runner.step() != Step::Propose {
            return Ok(());
        }
        if self.runner.current_proposal().is_some() {
            return Ok(());
        }
        if !self.runner.is_proposer()? {
            return Ok(());
        }

        let id = self.local.as_ref().ok_or(DriverError::NoLocalIdentity)?;
        let proposer = id.address();

        let candidates = self.collect_mempool_candidates();
        let evidences = std::mem::take(&mut self.pending_evidences);

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
                evidences,
            )
        });

        self.runner.propose(block)?;
        self.process_actions()
    }

    /// Traite une proposition reçue du réseau.
    ///
    /// **Buffering** : une proposition dont la hauteur dépasse la hauteur
    /// courante est mise de côté jusqu'au commit en cours. Sans cela, on
    /// la jetterait et le nœud ne voterait jamais pour la nouvelle
    /// hauteur.
    pub fn handle_proposal(&mut self, p: Proposal) -> Result<(), DriverError> {
        let current = self.runner.ctx().height;
        if p.height > current {
            if self.buffered_proposals.len() < MAX_BUFFERED_PER_KIND {
                self.buffered_proposals.push(p);
            }
            return Ok(());
        }
        if p.height < current {
            return Ok(());
        }

        match self.runner.on_proposal(p) {
            Ok(()) => self.process_actions(),
            Err(e) if is_stale(&e) => Ok(()),
            Err(e) => Err(DriverError::Consensus(e)),
        }
    }

    /// Traite une prevote reçue du réseau.
    ///
    /// **Buffering** : même logique que pour les propositions.
    pub fn handle_prevote(&mut self, v: Prevote) -> Result<(), DriverError> {
        let current = self.runner.ctx().height;
        if v.height > current {
            if self.buffered_prevotes.len() < MAX_BUFFERED_PER_KIND {
                self.buffered_prevotes.push(v);
            }
            return Ok(());
        }
        if v.height < current {
            return Ok(());
        }

        match self.runner.on_prevote(v) {
            Ok(()) => self.process_actions(),
            Err(e) if is_stale(&e) => Ok(()),
            Err(ConsensusError::DoublePrevote { first, second, .. }) => {
                let ev = build_double_prevote_evidence(&first, &second);
                self.pending_evidences.push(ev);
                Ok(())
            }
            Err(e) => Err(DriverError::Consensus(e)),
        }
    }

    /// Traite un precommit reçu du réseau.
    ///
    /// **Buffering** : même logique que pour les propositions.
    pub fn handle_precommit(&mut self, c: Precommit) -> Result<(), DriverError> {
        let current = self.runner.ctx().height;
        if c.height > current {
            if self.buffered_precommits.len() < MAX_BUFFERED_PER_KIND {
                self.buffered_precommits.push(c);
            }
            return Ok(());
        }
        if c.height < current {
            return Ok(());
        }

        match self.runner.on_precommit(c) {
            Ok(()) => self.process_actions(),
            Err(e) if is_stale(&e) => Ok(()),
            Err(ConsensusError::DoublePrecommit { first, second, .. }) => {
                let ev = build_double_precommit_evidence(&first, &second);
                self.pending_evidences.push(ev);
                Ok(())
            }
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

    /// Récupère et vide les messages sortants (self-loopback).
    pub fn drain_outbox(&mut self) -> Vec<OutgoingMessage> {
        std::mem::take(&mut self.outbox)
    }

    /// Récupère et vide les événements.
    pub fn drain_events(&mut self) -> Vec<DriverEvent> {
        std::mem::take(&mut self.events)
    }

    // --- Internes ----------------------------------------------------------

    fn collect_mempool_candidates(&self) -> Vec<Transaction> {
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

        let nonces: HashMap<NativeAddress, u64> = self.handle.with_node(|n| {
            senders
                .iter()
                .map(|s| (*s, n.state().nonce_of(s)))
                .collect()
        });

        let entries = self
            .handle
            .with_mempool(|pool| pool.select_for_block(MAX_TXS_PER_BLOCK, &nonces));

        entries.into_iter().map(|e| e.tx).collect()
    }

    fn prune_mempool(&self) {
        let senders: Vec<NativeAddress> = self.handle.with_mempool(|pool| {
            let mut s = HashSet::new();
            for h in pool.hashes() {
                if let Some(e) = pool.get(&h) {
                    s.insert(e.tx.sender);
                }
            }
            s.into_iter().collect()
        });

        let (nonces, new_base_fee) = self.handle.with_node(|n| {
            let nonces: HashMap<NativeAddress, u64> = senders
                .iter()
                .map(|s| (*s, n.state().nonce_of(s)))
                .collect();
            let bf = n.expected_base_fee().unwrap_or(INITIAL_BASE_FEE);
            (nonces, bf)
        });

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
                        if let Some(p2p) = &self.p2p {
                            let _ = p2p.broadcast_sync(NetworkMessage::Proposal(p.clone()));
                        }
                        self.outbox.push(OutgoingMessage::Proposal(p));
                    }
                    Action::BroadcastPrevote(v) => {
                        if let Some(p2p) = &self.p2p {
                            let _ = p2p.broadcast_sync(NetworkMessage::Prevote(v));
                        }
                        self.outbox.push(OutgoingMessage::Prevote(v));
                    }
                    Action::BroadcastPrecommit(c) => {
                        if let Some(p2p) = &self.p2p {
                            let _ = p2p.broadcast_sync(NetworkMessage::Precommit(c));
                        }
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

                        // Participants = precommitters (downtime).
                        let participants: Vec<NativeAddress> = certificate
                            .precommits
                            .iter()
                            .map(|e| e.validator_address)
                            .collect();

                        match self
                            .handle
                            .with_node_mut(|n| n.apply_block(&block, &participants))
                        {
                            Ok(_) => {}
                            // Déjà appliqué (double Committed via doublon P2P) :
                            // ce n'est pas fatal, on continue.
                            Err(NodeError::AlreadyApplied { .. }) => {}
                            Err(e) => return Err(DriverError::Node(e)),
                        }
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

                        // Vider le buffer : les messages reçus en avance
                        // pour la nouvelle hauteur sont maintenant acceptables.
                        self.drain_buffered_for_current_height();
                    }
                    Action::StartRound(new_round) => {
                        self.events.push(DriverEvent::RoundAdvanced(new_round));
                        let height = self.runner.ctx().height;
                        let parent_hash = self.runner.ctx().parent_hash;
                        self.runner.reset_for_round(height, new_round, parent_hash);
                        self.drain_buffered_for_current_height();
                    }
                }
            }
        }
        Err(DriverError::TooManyActions)
    }

    /// Réinjecte les messages bufferisés dont la hauteur correspond
    /// maintenant à la hauteur courante. Les autres restent en attente.
    fn drain_buffered_for_current_height(&mut self) {
        let target = self.runner.ctx().height;

        let proposals = std::mem::take(&mut self.buffered_proposals);
        for p in proposals {
            if p.height == target {
                let _ = self.handle_proposal(p);
            } else if p.height > target {
                self.buffered_proposals.push(p);
            }
            // p.height < target : obsolète, on jette.
        }

        let prevotes = std::mem::take(&mut self.buffered_prevotes);
        for v in prevotes {
            if v.height == target {
                let _ = self.handle_prevote(v);
            } else if v.height > target {
                self.buffered_prevotes.push(v);
            }
        }

        let precommits = std::mem::take(&mut self.buffered_precommits);
        for c in precommits {
            if c.height == target {
                let _ = self.handle_precommit(c);
            } else if c.height > target {
                self.buffered_precommits.push(c);
            }
        }
    }
}

impl std::fmt::Debug for Driver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Driver")
            .field("height", &self.current_height())
            .field("round", &self.current_round())
            .field("step", &self.current_step())
            .field("local", &self.local_address())
            .field("pending_evidences", &self.pending_evidences.len())
            .field("buffered_proposals", &self.buffered_proposals.len())
            .field("buffered_prevotes", &self.buffered_prevotes.len())
            .field("buffered_precommits", &self.buffered_precommits.len())
            .field("p2p_attached", &self.p2p.is_some())
            .finish_non_exhaustive()
    }
}

// --- Construction d'evidence (fonctions libres) ----------------------------

#[must_use]
fn build_double_prevote_evidence(first: &Prevote, second: &Prevote) -> Evidence {
    Evidence {
        version: sango_types::PROTOCOL_VERSION_V1,
        evidence_type: EvidenceType::DoublePrevote,
        chain_id: first.chain_id,
        epoch: first.epoch,
        height: first.height,
        round: first.round,
        validator_address: first.validator_address,
        message_1: ConsensusMessage {
            message_type: ConsensusMessageType::Prevote,
            canonical_payload: first.encode_unsigned_to_vec(),
            signature: first.validator_signature,
        },
        message_2: ConsensusMessage {
            message_type: ConsensusMessageType::Prevote,
            canonical_payload: second.encode_unsigned_to_vec(),
            signature: second.validator_signature,
        },
    }
}

#[must_use]
fn build_double_precommit_evidence(first: &Precommit, second: &Precommit) -> Evidence {
    Evidence {
        version: sango_types::PROTOCOL_VERSION_V1,
        evidence_type: EvidenceType::DoublePrecommit,
        chain_id: first.chain_id,
        epoch: first.epoch,
        height: first.height,
        round: first.round,
        validator_address: first.validator_address,
        message_1: ConsensusMessage {
            message_type: ConsensusMessageType::Precommit,
            canonical_payload: first.encode_unsigned_to_vec(),
            signature: first.validator_signature,
        },
        message_2: ConsensusMessage {
            message_type: ConsensusMessageType::Precommit,
            canonical_payload: second.encode_unsigned_to_vec(),
            signature: second.validator_signature,
        },
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
