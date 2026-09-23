//! Types de transport JSON-RPC 2.0.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::RpcError;

/// Requête JSON-RPC 2.0.
#[derive(Debug, Clone, Deserialize)]
pub struct Request {
    /// Doit valoir `"2.0"`.
    pub jsonrpc: String,
    /// Nom de la méthode (`sango_blockNumber`, etc.).
    pub method: String,
    /// Paramètres (tableau ou objet, optionnel).
    #[serde(default)]
    pub params: Value,
    /// Identifiant (nombre, string, ou null).
    #[serde(default)]
    pub id: Value,
}

/// Réponse JSON-RPC 2.0.
#[derive(Debug, Clone, Serialize)]
pub struct Response {
    /// Toujours `"2.0"`.
    pub jsonrpc: &'static str,
    /// Résultat en cas de succès.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Erreur en cas d'échec.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorObject>,
    /// Identifiant repris de la requête.
    pub id: Value,
}

/// Objet d'erreur JSON-RPC.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorObject {
    /// Code standard ou extension.
    pub code: i32,
    /// Message humain.
    pub message: String,
}

impl Response {
    /// Réponse succès.
    #[must_use]
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            result: Some(result),
            error: None,
            id,
        }
    }

    /// Réponse erreur.
    #[must_use]
    pub fn failure(id: Value, error: RpcError) -> Self {
        Self {
            jsonrpc: "2.0",
            result: None,
            error: Some(ErrorObject {
                code: error.code(),
                message: error.to_string(),
            }),
            id,
        }
    }
}
