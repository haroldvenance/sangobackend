//! Erreurs du crate P2P.

use thiserror::Error;

/// Erreur produite par une opération P2P.
#[derive(Debug, Error)]
pub enum P2pError {
    /// Erreur de transport libp2p.
    #[error("transport: {0}")]
    Transport(String),

    /// Erreur de décodage d'un message.
    #[error("codec: {0}")]
    Codec(#[from] sango_codec::CodecError),

    /// Type de message inconnu.
    #[error("unknown message type: {0}")]
    UnknownMessageType(u8),

    /// Erreur de configuration (adresse invalide, etc.).
    #[error("config: {0}")]
    Config(String),

    /// Erreur d'I/O.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// Le service P2P n'est pas en cours d'exécution.
    #[error("service not running")]
    NotRunning,

    /// Le canal de communication avec le service est fermé.
    #[error("service channel closed")]
    ChannelClosed,

    /// Erreur de souscription à un topic.
    #[error("subscription: {0}")]
    Subscription(String),
}
