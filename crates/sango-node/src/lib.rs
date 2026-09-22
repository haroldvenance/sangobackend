//! `sango-node` — orchestration d'un nœud Sango V1.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod base_fee;
mod diff;
mod driver;
mod error;
mod node;

pub use base_fee::{
    next_base_fee, BASE_FEE_MAX_CHANGE_DENOMINATOR, INITIAL_BASE_FEE, MIN_BASE_FEE,
};
pub use diff::{diff_state, StateDiff};
pub use driver::{Driver, DriverError, DriverEvent, OutgoingMessage};
pub use error::NodeError;
pub use node::Node;
