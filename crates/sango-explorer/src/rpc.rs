//! Helpers typés au-dessus de [`sango_wallet::RpcClient`].
//!
//! Chaque helper :
//! 1. appelle la méthode RPC ;
//! 2. parse le JSON retourné ;
//! 3. décode les bytes canoniques (si applicable).
//!
//! Aucune logique métier : l'explorer lit, il ne calcule pas.

use sango_codec::Decode;
use sango_primitives::{Hash32, NativeAddress};
use sango_types::{Block, EvmTx, Transaction, Tx};
use sango_wallet::RpcClient;
use serde_json::{json, Value};

use crate::error::ExplorerError;

/// Wrapper typé sur le client RPC.
pub struct Rpc {
    client: RpcClient,
}

impl Rpc {
    /// Construit un wrapper.
    #[must_use]
    pub fn new(endpoint: &str) -> Self {
        Self {
            client: RpcClient::new(endpoint),
        }
    }

    /// Appel brut (pour les pages qui n'ont pas besoin de typer).
    pub fn raw(&self, method: &str, params: Value) -> Result<Value, ExplorerError> {
        self.client.call(method, params).map_err(ExplorerError::Rpc)
    }

    // --- Info chaîne -------------------------------------------------------

    /// Hauteur du tip.
    pub fn block_number(&self) -> Result<Option<u64>, ExplorerError> {
        let v = self.raw("sango_blockNumber", json!([]))?;
        if v.is_null() {
            return Ok(None);
        }
        v.as_u64()
            .map(Some)
            .ok_or_else(|| ExplorerError::Parse("blockNumber: expected u64 or null".into()))
    }

    /// Info chaîne complète (`chainId`, `height`, `validatorCount`,
    /// `protocolVersion`).
    pub fn chain_info(&self) -> Result<Value, ExplorerError> {
        self.raw("sango_chainInfo", json!([]))
    }

    // --- Blocs -------------------------------------------------------------

    /// Lit un bloc par hauteur, décodé.
    pub fn get_block(&self, height: u64) -> Result<Option<Block>, ExplorerError> {
        let v = self.raw("sango_getBlock", json!([height]))?;
        if v.is_null() {
            return Ok(None);
        }
        let bytes_hex = v
            .get("bytes")
            .and_then(|x| x.as_str())
            .ok_or_else(|| ExplorerError::Parse("getBlock: missing bytes".into()))?;
        let bytes = hex::decode(bytes_hex.trim_start_matches("0x"))
            .map_err(|e| ExplorerError::Parse(format!("getBlock hex: {e}")))?;
        let block = Block::decode_exact(&bytes)
            .map_err(|e| ExplorerError::Parse(format!("getBlock decode: {e}")))?;
        Ok(Some(block))
    }

    // --- Transactions ------------------------------------------------------

    /// Lit une tx par hash, décodée (native ou EVM) + localisation.
    pub fn get_transaction(&self, hash: &Hash32) -> Result<Option<TxWithLoc>, ExplorerError> {
        let v = self.raw(
            "sango_getTransactionByHash",
            json!([format!("0x{}", hash.to_hex())]),
        )?;
        if v.is_null() {
            return Ok(None);
        }
        let tx_hex = v
            .get("tx")
            .and_then(|x| x.as_str())
            .ok_or_else(|| ExplorerError::Parse("tx: missing tx".into()))?;
        let kind = v.get("kind").and_then(|x| x.as_str()).unwrap_or("native");
        let bytes = hex::decode(tx_hex.trim_start_matches("0x"))
            .map_err(|e| ExplorerError::Parse(format!("tx hex: {e}")))?;
        let tx: Tx = match kind {
            "native" => Tx::Native(
                Transaction::decode_exact(&bytes)
                    .map_err(|e| ExplorerError::Parse(format!("tx decode native: {e}")))?,
            ),
            "evm" => Tx::Evm(
                EvmTx::decode_ethereum_typed(&bytes)
                    .map_err(|e| ExplorerError::Parse(format!("tx decode evm: {e}")))?,
            ),
            other => {
                return Err(ExplorerError::Parse(format!("tx: unknown kind {other}")));
            }
        };
        Ok(Some(TxWithLoc {
            tx,
            block_height: v.get("blockHeight").and_then(|x| x.as_u64()).unwrap_or(0),
            block_hash: v
                .get("blockHash")
                .and_then(|x| x.as_str())
                .and_then(|s| Hash32::from_hex(s).ok()),
            tx_index: v.get("txIndex").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
        }))
    }

    /// Txs natives d'une adresse, paginées.
    pub fn txs_by_address(
        &self,
        addr: &NativeAddress,
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<TxWithLoc>, u64), ExplorerError> {
        let v = self.raw(
            "sango_getTransactionsByAddress",
            json!([format!("0x{}", addr.to_hex()), limit, offset]),
        )?;
        let total = v.get("total").and_then(|x| x.as_u64()).unwrap_or(0);
        let items = v
            .get("items")
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default();

        let mut out = Vec::with_capacity(items.len());
        for item in items {
            let tx_hex = item
                .get("tx")
                .and_then(|x| x.as_str())
                .ok_or_else(|| ExplorerError::Parse("item: missing tx".into()))?;
            let kind = item
                .get("kind")
                .and_then(|x| x.as_str())
                .unwrap_or("native");
            let bytes = hex::decode(tx_hex.trim_start_matches("0x"))
                .map_err(|e| ExplorerError::Parse(format!("item hex: {e}")))?;
            let tx: Tx = match kind {
                "native" => Tx::Native(
                    Transaction::decode_exact(&bytes)
                        .map_err(|e| ExplorerError::Parse(format!("item decode: {e}")))?,
                ),
                "evm" => Tx::Evm(
                    EvmTx::decode_ethereum_typed(&bytes)
                        .map_err(|e| ExplorerError::Parse(format!("item decode evm: {e}")))?,
                ),
                other => {
                    return Err(ExplorerError::Parse(format!("item: unknown kind {other}")));
                }
            };
            out.push(TxWithLoc {
                tx,
                block_height: item
                    .get("blockHeight")
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0),
                block_hash: item
                    .get("blockHash")
                    .and_then(|x| x.as_str())
                    .and_then(|s| Hash32::from_hex(s).ok()),
                tx_index: item.get("txIndex").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
            });
        }
        Ok((out, total))
    }

    // --- Comptes -----------------------------------------------------------

    /// Lit un compte natif.
    pub fn get_account(&self, addr: &NativeAddress) -> Result<Option<AccountView>, ExplorerError> {
        let v = self.raw("sango_getAccount", json!([format!("0x{}", addr.to_hex())]))?;
        if v.is_null() {
            return Ok(None);
        }
        Ok(Some(AccountView {
            public_key: v
                .get("publicKey")
                .and_then(|x| x.as_str())
                .map(str::to_string),
            balance: v
                .get("balance")
                .and_then(|x| x.as_str())
                .and_then(|s| s.parse::<u128>().ok())
                .unwrap_or(0),
            nonce: v.get("nonce").and_then(|x| x.as_u64()).unwrap_or(0),
        }))
    }

    // --- Staking -----------------------------------------------------------

    /// Liste tous les validateurs.
    pub fn get_validators(&self) -> Result<Vec<Value>, ExplorerError> {
        let v = self.raw("sango_getValidators", json!([]))?;
        v.as_array()
            .cloned()
            .ok_or_else(|| ExplorerError::Parse("getValidators: expected array".into()))
    }

    /// Info validateur pour une adresse.
    pub fn get_validator_info(&self, addr: &NativeAddress) -> Result<Option<Value>, ExplorerError> {
        let v = self.raw(
            "sango_getValidatorInfo",
            json!([format!("0x{}", addr.to_hex())]),
        )?;
        Ok(if v.is_null() { None } else { Some(v) })
    }

    /// Délégations émises par une adresse.
    pub fn get_delegations(&self, addr: &NativeAddress) -> Result<Vec<Value>, ExplorerError> {
        let v = self.raw(
            "sango_getDelegations",
            json!([format!("0x{}", addr.to_hex())]),
        )?;
        v.as_array()
            .cloned()
            .ok_or_else(|| ExplorerError::Parse("getDelegations: expected array".into()))
    }

    /// Unbondings en attente pour une adresse.
    pub fn get_pending_unbondings(
        &self,
        addr: &NativeAddress,
    ) -> Result<Vec<Value>, ExplorerError> {
        let v = self.raw(
            "sango_getPendingUnbondings",
            json!([format!("0x{}", addr.to_hex())]),
        )?;
        v.as_array()
            .cloned()
            .ok_or_else(|| ExplorerError::Parse("getPendingUnbondings: expected array".into()))
    }
}

/// Transaction décodée + localisation (vue explorer).
#[derive(Debug)]
pub struct TxWithLoc {
    /// La tx.
    pub tx: Tx,
    /// Hauteur du bloc contenant la tx.
    pub block_height: u64,
    /// Hash du bloc (optionnel).
    pub block_hash: Option<Hash32>,
    /// Index dans le bloc.
    pub tx_index: u32,
}

/// Vue compte natif (explorer).
#[derive(Debug)]
pub struct AccountView {
    /// Clé publique (hex) ou `None` si ghost.
    pub public_key: Option<String>,
    /// Solde en base units.
    pub balance: u128,
    /// Nonce.
    pub nonce: u64,
}
