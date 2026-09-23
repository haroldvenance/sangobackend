//! `sango-node` — orchestration d'un nœud Sango V1.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod base_fee;
pub mod config;
mod diff;
mod driver;
mod error;
mod node;
mod node_handle;
mod rpc_backend;

pub use base_fee::{
    next_base_fee, BASE_FEE_MAX_CHANGE_DENOMINATOR, INITIAL_BASE_FEE, MIN_BASE_FEE,
};
pub use config::{ConfigError, NodeConfig, RuntimeGenesis};
pub use diff::{diff_state, StateDiff};
pub use driver::{Driver, DriverError, DriverEvent, OutgoingMessage};
pub use error::NodeError;
pub use node::Node;
pub use node_handle::NodeHandle;
pub use rpc_backend::NodeBackend;
