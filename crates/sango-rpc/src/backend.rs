//! Interface abstraite entre le serveur RPC et l'implémentation du nœud.
//!
//! Le serveur ne dépend **pas** de `sango-node` : il appelle uniquement les
//! méthodes de ce trait. Cela permet :
//!
//! - de tester le serveur avec un backend factice ;
//! - de remplacer l'implémentation (mock, node réel, proxy) sans changer le
//!   serveur.

use sango_primitives::{Amount, ChainId32, Hash32, NativeAddress};
use sango_types::{Block, NativeAccount, Transaction, ValidatorInfo};

use crate::error::RpcError;

/// Vue en lecture + en écriture minimale d'un nœud Sango.
pub trait RpcBackend: Send + Sync + 'static {
    /// Chain ID natif.
    fn chain_id(&self) -> ChainId32;

    /// Hauteur du dernier bloc appliqué (`None` = aucun bloc).
    fn block_number(&self) -> Option<u64>;

    /// Récupère un bloc par hauteur.
    fn get_block_by_height(&self, height: u64) -> Option<Block>;

    /// Récupère un compte natif par adresse.
    fn get_account(&self, address: &NativeAddress) -> Option<NativeAccount>;

    /// Solde d'une adresse (base units). Retourne 0 si absent.
    fn get_balance(&self, address: &NativeAddress) -> Amount;

    /// Tous les validateurs enregistrés.
    fn get_validators(&self) -> Vec<ValidatorInfo>;

    /// Soumet une transaction au mempool.
    ///
    /// Retourne le hash de la transaction acceptée.
    fn send_transaction(&self, tx: &Transaction) -> Result<Hash32, RpcError>;
}
