//! Topics gossipsub.

/// Topic pour les messages consensus (proposal / prevote / precommit).
pub const TOPIC_CONSENSUS: &str = "/sango/consensus/1.0.0";

/// Topic pour les transactions (mempool).
pub const TOPIC_TX: &str = "/sango/tx/1.0.0";

/// Topic pour les blocs (synchronisation).
pub const TOPIC_BLOCK: &str = "/sango/block/1.0.0";

/// Tous les topics, dans l'ordre canonique.
pub const ALL_TOPICS: &[&str] = &[TOPIC_CONSENSUS, TOPIC_TX, TOPIC_BLOCK];
