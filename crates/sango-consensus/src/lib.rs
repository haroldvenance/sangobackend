//! `sango-consensus` — consensus PoS + BFT de Sango V1.
//!
//! ## Portée de cette première étape (C1)
//!
//! Ce crate fournit les **briques** du consensus, sans la machine d'état
//! complète (voir C2 pour le driver : timeouts, transitions de round,
//! intégration avec `sango-node`) :
//!
//! - [`ValidatorSet`] : ensemble actif, ordonné, avec quorum `> 2/3` ;
//! - [`select_proposer`] : sélection déterministe pondérée par voting power ;
//! - [`VoteTracker`] : accumulation des prevotes/precommits, détection des
//!   double-votes, construction des certificats ;
//! - [`ConsensusState`] : état local de verrouillage d'un validateur
//!   (Freeze sections 40 à 42).
//!
//! ## Invariants du Freeze
//!
//! - Le **voting power** est recalculé localement à partir du validator set,
//!   jamais déduit d'un certificat.
//! - Le **proposer** est sélectionné de manière **déterministe** et
//!   **proportionnelle** au voting power, sans flottants.
//! - Un validateur **ne peut produire qu'un prevote et un precommit par
//!   `(height, round)`**.
//! - Un **timeout ne déverrouille jamais** un validateur ; seul un PoLC
//!   d'un bloc différent à un round strictement supérieur le permet.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod proposer;
mod state;
mod validator_set;
mod vote_tracker;

pub use error::ConsensusError;
pub use proposer::select_proposer;
pub use state::{ConsensusState, PolcOutcome};
pub use validator_set::{Validator, ValidatorSet};
pub use vote_tracker::VoteTracker;
