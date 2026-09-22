//! `sango-consensus` — consensus PoS + BFT de Sango V1.
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────┐
//! │                       Driver                             │
//! │  (horloge, réseau, I/O, application de bloc)             │
//! └─────────────┬────────────────────────────────────────────┘
//!               │ events
//!               ▼
//! ┌──────────────────────────────────────────────────────────┐
//! │                    RoundRunner                           │
//! │  (machine d'état pure pour un (height, round))           │
//! │                                                          │
//! │   ConsensusState  ◄──┐  VoteTracker                      │
//! │   (locks/valid)      │  (accumulation, quorum)           │
//! │                      │                                   │
//! │   Step ◄─────────────┘                                   │
//! └─────────────┬────────────────────────────────────────────┘
//!               │ actions
//!               ▼
//! ┌──────────────────────────────────────────────────────────┐
//! │                       Driver                             │
//! │  (broadcast, persistence, apply_block)                   │
//! └──────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Responsabilités
//!
//! - [`ValidatorSet`] : ensemble actif, quorum `> 2/3`.
//! - [`select_proposer`] : sélection déterministe pondérée.
//! - [`VoteTracker`] : accumulation des votes, détection de double-vote,
//!   construction de certificats.
//! - [`ConsensusState`] : locks / valid / unlock (Freeze §40-42).
//! - [`verify_proposal`] : vérifications statiques sur une proposition.
//! - [`Step`], [`Action`] : la machine d'état et ses sorties.
//! - [`TimeoutConfig`] : formules normatives des timeouts (§17).
//!
//! ## Invariants du Freeze
//!
//! - Le **voting power** est recalculé localement à partir du validator set.
//! - Le **proposer** est sélectionné de manière déterministe et
//!   proportionnelle au voting power, sans flottants.
//! - Un validateur **ne peut produire qu'un prevote et un precommit par
//!   `(height, round)`**.
//! - Un **timeout ne déverrouille jamais** un validateur ; seul un PoLC
//!   d'un bloc différent à un round strictement supérieur le permet.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod proposal_verify;
mod proposer;
mod runner;
mod state;
mod step;
mod timeouts;
mod validator_set;
mod vote_tracker;

pub use error::ConsensusError;
pub use proposal_verify::{verify_proposal, ProposalContext};
pub use proposer::select_proposer;
pub use runner::{LocalIdentity, RoundContext, RoundRunner};
pub use state::{ConsensusState, PolcOutcome};
pub use step::{Action, Step};
pub use timeouts::TimeoutConfig;
pub use validator_set::{Validator, ValidatorSet};
pub use vote_tracker::VoteTracker;
