//! Handle partagé sur un nœud et son mempool.
//!
//! Permet à plusieurs composants (`Driver`, `NodeBackend` RPC) de partager
//! un même `Node` et un même `Mempool` sans en prendre possession
//! exclusivement.

use std::sync::{Arc, Mutex, RwLock};

use sango_mempool::{EvmMempool, Mempool};

use crate::node::Node;

/// Handle clonable sur `Node` + `Mempool`.
///
/// `Node` est protégé par un `RwLock` : plusieurs lecteurs (RPC) peuvent
/// lire en parallèle, tandis qu'un seul écrivain (Driver) peut appliquer
/// un bloc à la fois.
///
/// `Mempool` est protégé par un `Mutex` : accès exclusif, opérations
/// rapides.
#[derive(Clone)]
pub struct NodeHandle {
    node: Arc<RwLock<Node>>,
    mempool: Arc<Mutex<Mempool>>,
    /// Mempool EVM (4c.3.2). Séparé du mempool natif — voir la doc de
    /// `sango_mempool::EvmMempool`. Aucun bloc n'inclut encore de txs
    /// EVM (câblage en 4c.3.3).
    evm_mempool: Arc<Mutex<EvmMempool>>,
}

impl NodeHandle {
    /// Crée un handle à partir d'un `Node` fraîchement ouvert.
    ///
    /// Le mempool est initialisé vide avec la configuration par défaut.
    #[must_use]
    pub fn new(node: Node) -> Self {
        Self {
            node: Arc::new(RwLock::new(node)),
            mempool: Arc::new(Mutex::new(Mempool::default())),
            evm_mempool: Arc::new(Mutex::new(EvmMempool::default())),
        }
    }

    /// Crée un handle avec une configuration de mempool personnalisée.
    #[must_use]
    pub fn with_config(node: Node, mempool: Mempool) -> Self {
        Self {
            node: Arc::new(RwLock::new(node)),
            mempool: Arc::new(Mutex::new(mempool)),
            evm_mempool: Arc::new(Mutex::new(EvmMempool::default())),
        }
    }

    /// Accès en lecture à `Node`.
    ///
    /// # Panics
    ///
    /// Si le `RwLock` est empoisonné (un thread a paniqué pendant un accès
    /// en écriture). Ne devrait pas arriver si le code critique n'entre
    /// pas en panique.
    pub fn with_node<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&Node) -> R,
    {
        let guard = self.node.read().expect("node lock poisoned");
        f(&guard)
    }

    /// Accès en écriture à `Node`.
    pub fn with_node_mut<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut Node) -> R,
    {
        let mut guard = self.node.write().expect("node lock poisoned");
        f(&mut guard)
    }

    /// Accès exclusif au mempool.
    pub fn with_mempool<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut Mempool) -> R,
    {
        let mut guard = self.mempool.lock().expect("mempool lock poisoned");
        f(&mut guard)
    }

    /// Accès exclusif au mempool EVM (4c.3.2).
    pub fn with_evm_mempool<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut EvmMempool) -> R,
    {
        let mut guard = self.evm_mempool.lock().expect("evm mempool lock poisoned");
        f(&mut guard)
    }

    /// Vrai si le pointeur interne vers le nœud est partagé avec `other`.
    ///
    /// Utile en tests.
    #[must_use]
    pub fn shares_node_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.node, &other.node)
    }
}

impl std::fmt::Debug for NodeHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeHandle").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sango_primitives::{Amount, ChainId32};
    use sango_types::NativeAccount;

    fn temp_node() -> (tempfile::TempDir, Node) {
        let dir = tempfile::tempdir().unwrap();
        let chain = ChainId32::from_bytes([0x11; 32]);
        let supply = Amount::from_sango(1_000_000_000).unwrap();
        let node = Node::open(dir.path(), chain, supply).unwrap();
        (dir, node)
    }

    #[test]
    fn handle_shares_node_clone() {
        let (_dir, node) = temp_node();
        let handle = NodeHandle::new(node);
        let clone = handle.clone();
        assert!(handle.shares_node_with(&clone));
    }

    #[test]
    fn with_node_read() {
        let (_dir, node) = temp_node();
        let handle = NodeHandle::new(node);
        let chain = handle.with_node(|n| n.chain_id());
        assert_eq!(chain, ChainId32::from_bytes([0x11; 32]));
    }

    #[test]
    fn with_node_mut_write() {
        let (_dir, node) = temp_node();
        let handle = NodeHandle::new(node);
        let addr = sango_primitives::NativeAddress::from_bytes([0xaa; 20]);
        handle.with_node_mut(|n| {
            // On ne peut pas muter directement state via Node public API,
            // mais on peut vérifier que le write lock s'acquiert sans deadlock.
            let _ = n.tip();
        });
        // Lecture après écriture : OK.
        let tip = handle.with_node(|n| n.tip());
        assert!(tip.is_none());
        let _ = addr;
    }

    #[test]
    fn with_mempool_read_write() {
        let (_dir, node) = temp_node();
        let handle = NodeHandle::new(node);
        handle.with_mempool(|pool| {
            assert!(pool.is_empty());
        });
    }

    #[test]
    fn account_visible_across_handles() {
        let (_dir, node) = temp_node();
        let handle = NodeHandle::new(node);
        let clone = handle.clone();

        // On stocke un compte via un handle et on le relit via l'autre.
        // Note : Node n'expose pas set_account publiquement, donc on
        // utilise with_node_mut pour un accès direct à l'état.
        let addr = sango_primitives::NativeAddress::from_bytes([0xbb; 20]);
        handle.with_node_mut(|n| {
            n.state_mut_for_test().set_account(NativeAccount {
                address: addr,
                public_key: sango_primitives::PublicKey::ZERO,
                balance: Amount::from_base_units(500),
                nonce: 3,
            });
        });
        let account = clone.with_node(|n| n.state().get_account(&addr));
        assert!(account.is_some());
        assert_eq!(account.unwrap().balance, Amount::from_base_units(500));
    }
}
