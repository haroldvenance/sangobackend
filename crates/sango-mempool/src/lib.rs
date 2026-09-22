//! `sango-mempool` — pool de transactions en attente Sango V1.
//!
//! ## Rôle
//!
//! Le mempool stocke les transactions valides reçues du réseau mais pas
//! encore incluses dans un bloc. Il fournit au producteur de bloc une
//! sélection ordonnée par prix effectif décroissant, en respectant les
//! dépendances de nonce.
//!
//! ## Non-consensus
//!
//! Le mempool **n'est pas** consensus-critical. Deux nœuds peuvent avoir
//! des mempools différents sans divergence de chaîne. Les règles qu'il
//! applique (admission, priorité, éviction) sont locales.
//!
//! ## Découplage
//!
//! `sango-mempool` ne dépend **pas** de `sango-state`. Les nonces des
//! émetteurs lui sont fournis par l'appelant (typiquement `sango-node`),
//! au moment de l'admission ou de la sélection.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod pool;

pub use error::MempoolError;
pub use pool::{Mempool, MempoolConfig, MempoolEntry};
