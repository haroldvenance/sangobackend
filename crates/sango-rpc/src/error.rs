//! Erreur produite par une méthode RPC.
//!
//! Le code suit la spécification JSON-RPC 2.0 (section 5.1), avec une
//! extension pour les erreurs spécifiques à Sango (espace réservé
//! `-32000` à `-32099`).

use thiserror::Error;

/// Erreur RPC.
#[derive(Debug, Error, Clone)]
pub enum RpcError {
    /// Erreur interne (bug, panne de stockage).
    #[error("{0}")]
    Internal(String),

    /// Paramètre invalide (mauvais type, hex mal formé, etc.).
    #[error("{0}")]
    InvalidParams(String),

    /// Entité absente (bloc, compte).
    #[error("{0}")]
    NotFound(String),

    /// Requête JSON-RPC invalide (version, format).
    #[error("{0}")]
    InvalidRequest(String),

    /// Méthode inconnue.
    #[error("method not found: {0}")]
    MethodNotFound(String),

    /// Transaction rejetée par le mempool ou l'état.
    #[error("{0}")]
    TransactionRejected(String),

    /// Trop de requêtes (rate limit IP ou batch trop volumineux).
    ///
    /// Code JSON-RPC `-32005` (espace réservé Sango). Le serveur HTTP
    /// répond avec un statut `429 Too Many Requests` quand cette erreur
    /// est levée au niveau du rate limiter, mais le JSON-RPC peut aussi
    /// la transporter dans un `200 OK` si elle est levée au niveau du
    /// batch cap.
    #[error("{0}")]
    RateLimited(String),
}

impl RpcError {
    /// Code JSON-RPC standard.
    #[must_use]
    pub fn code(&self) -> i32 {
        match self {
            RpcError::InvalidRequest(_) => -32600,
            RpcError::MethodNotFound(_) => -32601,
            RpcError::InvalidParams(_) => -32602,
            RpcError::Internal(_) => -32603,
            RpcError::NotFound(_) => -32001,
            RpcError::TransactionRejected(_) => -32010,
            RpcError::RateLimited(_) => -32005,
        }
    }
}