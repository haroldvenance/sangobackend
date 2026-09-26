//! Interface abstraite entre le serveur RPC et l'implémentation du nœud.
//!
//! Le serveur ne dépend **pas** de `sango-node` : il appelle uniquement les
//! méthodes de ce trait. Cela permet :
//!
//! - de tester le serveur avec un backend factice ;
//! - de remplacer l'implémentation (mock, node réel, proxy) sans changer le
//!   serveur.

use sango_primitives::{Amount, ChainId32, EvmAddress, Hash32, NativeAddress, U256};
use sango_types::{Block, NativeAccount, Transaction, ValidatorInfo};

use crate::error::RpcError;

/// Requête `eth_call` / `eth_estimateGas`.
///
/// Représente l'objet `{from, to, gas, gasPrice, value, data}` du standard
/// Ethereum. Tous les champs sont optionnels dans le JSON-RPC ; les valeurs
/// par défaut sont appliquées par l'implémentation (`sango-node`).
#[derive(Clone, Debug)]
pub struct EthCallRequest {
    /// Adresse de l'appelant. `EvmAddress::ZERO` si non fournie.
    pub from: EvmAddress,
    /// Destination. `None` = création de contrat.
    pub to: Option<EvmAddress>,
    /// Gas limite. `None` → valeur par défaut de l'implémentation
    /// (recommandé : `EVM_GAS_LIMIT = 30_000_000`).
    pub gas: Option<u64>,
    /// Prix du gas. `None` → base fee courante du bloc.
    pub gas_price: Option<U256>,
    /// Montant transféré (base units). Défaut : 0.
    pub value: U256,
    /// Calldata (call) ou init code (create).
    pub data: Vec<u8>,
}

/// Résultat d'un `eth_call`.
#[derive(Clone, Debug)]
pub struct EthCallResult {
    /// Vrai si l'exécution a réussi (pas de revert / halt).
    pub success: bool,
    /// Données de retour (call uniquement).
    pub output: Vec<u8>,
    /// Gas consommé.
    pub gas_used: u64,
}

// --- Types eth_getLogs ----------------------------------------------------

/// Tag de bloc pour les filtres (`eth_getLogs`, `eth_getProof`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockTag {
    /// Dernier bloc connu (`latest`).
    Latest,
    /// Bloc genesis (`earliest`).
    Earliest,
    /// Bloc en cours (`pending`). En V1, traité comme `latest`.
    Pending,
    /// Numéro de bloc explicite.
    Number(u64),
}

/// Filtre `eth_getLogs`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EthLogFilter {
    /// Bloc de début. `None` = `latest`.
    pub from_block: Option<BlockTag>,
    /// Bloc de fin. `None` = `latest`.
    pub to_block: Option<BlockTag>,
    /// Filtre sur un bloc précis par hash (override `from`/`to`).
    pub block_hash: Option<Hash32>,
    /// Adresses à garder. Vide = toutes.
    pub addresses: Vec<EvmAddress>,
    /// Filtres positionnels de topics. Vide = aucune contrainte.
    ///
    /// `topics[i] = Some(v)` = la i-ème topic doit appartenir à `v`.
    /// `topics[i] = None` = wildcard à la position i.
    pub topics: Vec<Option<Vec<Hash32>>>,
}

/// Log EVM au format RPC Ethereum.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EthLog {
    /// Adresse du contrat émetteur.
    pub address: EvmAddress,
    /// Topics indexés.
    pub topics: Vec<Hash32>,
    /// Données non indexées.
    pub data: Vec<u8>,
    /// Hauteur du bloc.
    pub block_number: u64,
    /// Hash du bloc.
    pub block_hash: Hash32,
    /// Hash de la transaction.
    pub transaction_hash: Hash32,
    /// Index de la transaction dans le bloc.
    pub transaction_index: u64,
    /// Index du log dans le bloc (position absolue, tous txs confondus).
    pub log_index: u64,
    /// Toujours `false` en V1 (pas de réorganisation).
    pub removed: bool,
}

// --- Types eth_getProof (EIP-1186) ----------------------------------------

/// Preuve MPT pour un slot de storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EthStorageProof {
    /// Clé de storage (U256).
    pub key: U256,
    /// Valeur du slot (`0` si absent).
    pub value: U256,
    /// Nœuds RLP-encodés traversés (preuve MPT).
    pub proof: Vec<Vec<u8>>,
}

/// Preuve MPT pour un compte EVM (EIP-1186).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EthProof {
    /// Adresse EVM concernée.
    pub address: EvmAddress,
    /// Nœuds RLP-encodés vers la feuille du compte.
    pub account_proof: Vec<Vec<u8>>,
    /// Solde du compte.
    pub balance: U256,
    /// `Keccak256(code)` — `empty_code_hash()` si pas de code.
    pub code_hash: Hash32,
    /// Nonce du compte.
    pub nonce: u64,
    /// Racine du storage trie du compte.
    pub storage_hash: Hash32,
    /// Preuves individuelles pour chaque slot demandé.
    pub storage_proof: Vec<EthStorageProof>,
}

/// Vue en lecture + en écriture minimale d'un nœud Sango.
///
/// ## Compatibilité
///
/// Les méthodes `eth_*` ont des **implémentations par défaut** qui renvoient
/// des valeurs neutres (`0`, vide, ou une erreur explicite). Un backend qui
/// ne supporte pas l'EVM n'a rien à implémenter.
pub trait RpcBackend: Send + Sync + 'static {
    // --- Méthodes natives (obligatoires) ----------------------------------

    /// Chain ID natif.
    fn chain_id(&self) -> ChainId32;

    /// Hauteur du dernier bloc appliqué (`None` = aucun bloc).
    fn block_number(&self) -> Option<u64>;

    /// Récupère un bloc par hauteur.
    fn get_block_by_height(&self, height: u64) -> Option<Block>;

    /// Récupère un compte natif par adresse.
    fn get_account(&self, address: &NativeAddress) -> Option<NativeAccount>;

    /// Solde d'une adresse native (base units). Retourne 0 si absent.
    fn get_balance(&self, address: &NativeAddress) -> Amount;

    /// Tous les validateurs enregistrés.
    fn get_validators(&self) -> Vec<ValidatorInfo>;

    /// Soumet une transaction native au mempool.
    fn send_transaction(&self, tx: &Transaction) -> Result<Hash32, RpcError>;

    // --- Méthodes EVM (optionnelles, valeurs par défaut) ------------------

    /// Chain ID EVM (`eth_chainId`). Défaut : 0.
    fn eth_chain_id(&self) -> u64 {
        0
    }

    /// Prix du gas courant (`eth_gasPrice`). Défaut : 0.
    fn eth_gas_price(&self) -> U256 {
        U256::ZERO
    }

    /// Solde EVM d'une adresse (`eth_getBalance`). Défaut : 0.
    fn eth_get_balance(&self, _address: &EvmAddress) -> U256 {
        U256::ZERO
    }

    /// Nonce EVM d'une adresse (`eth_getTransactionCount`). Défaut : 0.
    fn eth_get_transaction_count(&self, _address: &EvmAddress) -> u64 {
        0
    }

    /// Bytecode EVM d'un compte (`eth_getCode`). Défaut : vide.
    fn eth_get_code(&self, _address: &EvmAddress) -> Vec<u8> {
        Vec::new()
    }

    /// Slot de storage EVM (`eth_getStorageAt`). Défaut : 0.
    fn eth_get_storage_at(&self, _address: &EvmAddress, _slot: U256) -> U256 {
        U256::ZERO
    }

    /// Exécution read-only (`eth_call`). Défaut : non supporté.
    fn eth_call(&self, _req: &EthCallRequest) -> Result<EthCallResult, RpcError> {
        Err(RpcError::Internal(
            "eth_call not supported by this backend".into(),
        ))
    }

    /// Estimation de gas (`eth_estimateGas`). Défaut : non supporté.
    fn eth_estimate_gas(&self, _req: &EthCallRequest) -> Result<u64, RpcError> {
        Err(RpcError::Internal(
            "eth_estimateGas not supported by this backend".into(),
        ))
    }

    /// Soumet une transaction EVM brute (typed-transaction Ethereum) au
    /// mempool EVM (`eth_sendRawTransaction`). Défaut : non supporté.
    ///
    /// Le `raw` est décodé comme typed-transaction Ethereum
    /// (`0x00`/`0x01`/`0x02`/`0x04 || RLP(...)`). Le sender est
    /// **récupéré cryptographiquement** de la signature — il n'est jamais
    /// fourni par l'appelant.
    fn eth_send_raw_transaction(&self, _raw: &[u8]) -> Result<Hash32, RpcError> {
        Err(RpcError::Internal(
            "eth_sendRawTransaction not supported by this backend".into(),
        ))
    }

    /// Récupère les logs EVM filtrés (`eth_getLogs`). Défaut : non supporté.
    fn eth_get_logs(&self, _filter: &EthLogFilter) -> Result<Vec<EthLog>, RpcError> {
        Err(RpcError::Internal(
            "eth_getLogs not supported by this backend".into(),
        ))
    }

    /// Génère une preuve MPT EIP-1186 (`eth_getProof`). Défaut : non supporté.
    ///
    /// Le paramètre `block` est ignoré en V1 : seul le tip est disponible.
    fn eth_get_proof(
        &self,
        _address: &EvmAddress,
        _storage_keys: &[U256],
        _block: Option<u64>,
    ) -> Result<EthProof, RpcError> {
        Err(RpcError::Internal(
            "eth_getProof not supported by this backend".into(),
        ))
    }
}
