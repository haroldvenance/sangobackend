//! `sango-types` — structures composites du protocole Sango V1.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod account;
mod block;
mod chain_tip;
mod consensus;
mod error;
mod evidence;
mod evidence_record;
mod genesis;
mod header;
mod receipt;
mod staking;
mod transaction;

pub use account::NativeAccount;
pub use block::Block;
pub use chain_tip::ChainTip;
pub use consensus::{
    CommitCertificate, Precommit, PrecommitEntry, Prevote, PrevoteCertificate, PrevoteEntry,
    Proposal,
};
pub use error::TypeError;
pub use evidence::{ConsensusMessage, ConsensusMessageType, Evidence, EvidenceType};
pub use evidence_record::EvidenceRecord;
pub use genesis::{
    Allocation, ConsensusConfig, EvmConfig, EvmVersion, FeeConfig, Genesis, GenesisValidator,
    LockSchedule,
};
pub use header::BlockHeader;
pub use receipt::{EvmLog, LogsBloom, Receipt, ReceiptStatus, LOGS_BLOOM_BYTES, MAX_LOG_TOPICS};
pub use staking::{params as staking_params, Delegation, ValidatorInfo};
pub use transaction::{Transaction, TxKind};

/// Version courante du protocole Sango.
pub const PROTOCOL_VERSION_V1: u32 = 1;
