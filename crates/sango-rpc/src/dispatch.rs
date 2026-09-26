//! Dispatch JSON-RPC : méthode + params → résultat.

use serde_json::{json, Value};

use sango_codec::Decode as _;
use sango_primitives::{EvmAddress, Hash32, NativeAddress, U256};
use sango_types::Transaction;

use crate::backend::{EthCallRequest, RpcBackend};
use crate::error::RpcError;
use crate::json::{Request, Response};

/// Point d'entrée : traite une requête, produit toujours une réponse.
#[must_use]
pub fn dispatch<B: RpcBackend>(backend: &B, req: Request) -> Response {
    let id = req.id.clone();

    if req.jsonrpc != "2.0" {
        return Response::failure(
            id,
            RpcError::InvalidRequest(format!("unsupported jsonrpc version: {}", req.jsonrpc)),
        );
    }

    match handle(backend, &req.method, &req.params) {
        Ok(v) => Response::success(id, v),
        Err(e) => Response::failure(id, e),
    }
}

fn handle<B: RpcBackend>(backend: &B, method: &str, params: &Value) -> Result<Value, RpcError> {
    match method {
        // --- Sango natif ---
        "sango_chainId" => sango_chain_id(backend),
        "sango_blockNumber" => sango_block_number(backend),
        "sango_getBlock" => sango_get_block(backend, params),
        "sango_getAccount" => sango_get_account(backend, params),
        "sango_getBalance" => sango_get_balance(backend, params),
        "sango_getValidators" => sango_get_validators(backend),
        "sango_sendTransaction" => sango_send_transaction(backend, params),
        "sango_chainInfo" => sango_chain_info(backend),
        "sango_baseFee" => sango_base_fee(backend),
        "sango_getTransactionByHash" => sango_get_transaction_by_hash(backend, params),

        // --- Ethereum-compatible ---
        "eth_chainId" => eth_chain_id(backend),
        "eth_blockNumber" => eth_block_number(backend),
        "eth_gasPrice" => eth_gas_price(backend),
        "eth_getBalance" => eth_get_balance(backend, params),
        "eth_getTransactionCount" => eth_get_transaction_count(backend, params),
        "eth_getCode" => eth_get_code(backend, params),
        "eth_getStorageAt" => eth_get_storage_at(backend, params),
        "eth_call" => eth_call(backend, params),
        "eth_estimateGas" => eth_estimate_gas(backend, params),
        "eth_sendRawTransaction" => eth_send_raw_transaction(backend, params),
        "eth_getLogs" => eth_get_logs(backend, params),
        "eth_getProof" => eth_get_proof(backend, params),

        other => Err(RpcError::MethodNotFound(other.to_string())),
    }
}

// --- Méthodes natives ------------------------------------------------------

fn sango_chain_id<B: RpcBackend>(backend: &B) -> Result<Value, RpcError> {
    let id = backend.chain_id();
    Ok(json!(format!("0x{}", id.to_hex())))
}

fn sango_block_number<B: RpcBackend>(backend: &B) -> Result<Value, RpcError> {
    match backend.block_number() {
        None => Ok(Value::Null),
        Some(h) => Ok(json!(h)),
    }
}

fn sango_get_block<B: RpcBackend>(backend: &B, params: &Value) -> Result<Value, RpcError> {
    let height = parse_u64_param(params, 0, "height")?;
    match backend.get_block_by_height(height) {
        None => Ok(Value::Null),
        Some(block) => {
            let hash = block.hash();
            let bytes = sango_codec::Encode::encode_to_vec(&block);
            Ok(json!({
                "height": height,
                "hash": format!("0x{}", hash.to_hex()),
                "bytes": format!("0x{}", hex::encode(bytes)),
            }))
        }
    }
}

fn sango_get_account<B: RpcBackend>(backend: &B, params: &Value) -> Result<Value, RpcError> {
    let address = parse_address_param(params, 0, "address")?;
    match backend.get_account(&address) {
        None => Ok(Value::Null),
        Some(acc) => {
            let pk_hex = if acc.has_registered_public_key() {
                Some(format!("0x{}", acc.public_key.to_hex()))
            } else {
                None
            };
            Ok(json!({
                "address": format!("0x{}", acc.address.to_hex()),
                "publicKey": pk_hex,
                "balance": acc.balance.base_units().to_string(),
                "nonce": acc.nonce,
            }))
        }
    }
}

fn sango_get_balance<B: RpcBackend>(backend: &B, params: &Value) -> Result<Value, RpcError> {
    let address = parse_address_param(params, 0, "address")?;
    let balance = backend.get_balance(&address);
    Ok(json!(balance.base_units().to_string()))
}

fn sango_get_validators<B: RpcBackend>(backend: &B) -> Result<Value, RpcError> {
    let validators = backend.get_validators();
    let array: Vec<Value> = validators
        .into_iter()
        .map(|v| {
            json!({
                "address": format!("0x{}", v.address.to_hex()),
                "publicKey": format!("0x{}", v.public_key.to_hex()),
                "selfStake": v.self_stake.base_units().to_string(),
                "totalDelegated": v.total_delegated.base_units().to_string(),
                "votingPower": v.voting_power().base_units().to_string(),
                "commissionBps": v.commission_bps,
                "jailed": v.jailed,
            })
        })
        .collect();
    Ok(Value::Array(array))
}

fn sango_send_transaction<B: RpcBackend>(backend: &B, params: &Value) -> Result<Value, RpcError> {
    let bytes_hex = params
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::InvalidParams("expected [hex_string]".into()))?;
    let raw = decode_hex(bytes_hex)?;
    let tx = Transaction::decode_exact(&raw)
        .map_err(|e| RpcError::InvalidParams(format!("decode tx: {e}")))?;
    let hash = backend.send_transaction(&tx)?;
    Ok(json!(format!("0x{}", hash.to_hex())))
}

fn sango_get_transaction_by_hash<B: RpcBackend>(
    backend: &B,
    params: &Value,
) -> Result<Value, RpcError> {
    let hash_hex = params
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::InvalidParams("expected [tx_hash_hex]".into()))?;
    let hash = Hash32::from_hex(hash_hex)
        .map_err(|e| RpcError::InvalidParams(format!("bad hash: {e}")))?;
    match backend.get_transaction_by_hash(&hash) {
        None => Ok(Value::Null),
        Some(tx) => {
            let bytes = sango_codec::Encode::encode_to_vec(&tx);
            Ok(json!({
                "hash": format!("0x{}", tx.hash().to_hex()),
                "tx": format!("0x{}", hex::encode(&bytes)),
            }))
        }
    }
}

fn sango_base_fee<B: RpcBackend>(backend: &B) -> Result<Value, RpcError> {
    // Décimale (string) en base units, cohérent avec `sango_getBalance`.
    Ok(json!(backend.sango_base_fee().to_string()))
}

fn sango_chain_info<B: RpcBackend>(backend: &B) -> Result<Value, RpcError> {
    let id = backend.chain_id();
    let height = backend.block_number();
    let validators = backend.get_validators().len();
    Ok(json!({
        "chainId": format!("0x{}", id.to_hex()),
        "height": height,
        "validatorCount": validators,
        "protocolVersion": sango_types::PROTOCOL_VERSION_V1,
    }))
}

// --- Méthodes Ethereum-compatibles ----------------------------------------

fn eth_chain_id<B: RpcBackend>(backend: &B) -> Result<Value, RpcError> {
    Ok(json!(format!("0x{:x}", backend.eth_chain_id())))
}

fn eth_block_number<B: RpcBackend>(backend: &B) -> Result<Value, RpcError> {
    match backend.block_number() {
        None => Ok(json!("0x0")),
        Some(h) => Ok(json!(format!("0x{h:x}"))),
    }
}

fn eth_gas_price<B: RpcBackend>(backend: &B) -> Result<Value, RpcError> {
    Ok(json!(format!("0x{:x}", backend.eth_gas_price())))
}

fn eth_get_balance<B: RpcBackend>(backend: &B, params: &Value) -> Result<Value, RpcError> {
    // Param 2 (block tag) ignoré : on interroge toujours le tip courant.
    let addr = parse_evm_address_param(params, 0, "address")?;
    let bal = backend.eth_get_balance(&addr);
    Ok(json!(format!("0x{:x}", bal)))
}

fn eth_get_transaction_count<B: RpcBackend>(
    backend: &B,
    params: &Value,
) -> Result<Value, RpcError> {
    let addr = parse_evm_address_param(params, 0, "address")?;
    let nonce = backend.eth_get_transaction_count(&addr);
    Ok(json!(format!("0x{nonce:x}")))
}

fn eth_get_code<B: RpcBackend>(backend: &B, params: &Value) -> Result<Value, RpcError> {
    let addr = parse_evm_address_param(params, 0, "address")?;
    let code = backend.eth_get_code(&addr);
    Ok(json!(format!("0x{}", hex::encode(code))))
}

fn eth_get_storage_at<B: RpcBackend>(backend: &B, params: &Value) -> Result<Value, RpcError> {
    let addr = parse_evm_address_param(params, 0, "address")?;
    let slot = parse_u256_param(params, 1, "slot")?;
    let v = backend.eth_get_storage_at(&addr, slot);
    Ok(json!(format!("0x{}", hex::encode(v.to_be_bytes::<32>()))))
}

fn eth_call<B: RpcBackend>(backend: &B, params: &Value) -> Result<Value, RpcError> {
    let req = parse_eth_call_request(params)?;
    let result = backend.eth_call(&req)?;
    Ok(json!(format!("0x{}", hex::encode(result.output))))
}

fn eth_estimate_gas<B: RpcBackend>(backend: &B, params: &Value) -> Result<Value, RpcError> {
    let req = parse_eth_call_request(params)?;
    let gas = backend.eth_estimate_gas(&req)?;
    Ok(json!(format!("0x{gas:x}")))
}

fn eth_send_raw_transaction<B: RpcBackend>(backend: &B, params: &Value) -> Result<Value, RpcError> {
    let raw_hex = params
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::InvalidParams("expected [raw_tx_hex]".into()))?;
    let raw = decode_hex(raw_hex)?;
    let hash = backend.eth_send_raw_transaction(&raw)?;
    Ok(json!(format!("0x{}", hash.to_hex())))
}

// --- eth_getLogs / eth_getProof -------------------------------------------

fn eth_get_logs<B: RpcBackend>(backend: &B, params: &Value) -> Result<Value, RpcError> {
    let filter = parse_log_filter(params)?;
    let logs = backend.eth_get_logs(&filter)?;
    Ok(serialize_logs(&logs))
}

fn eth_get_proof<B: RpcBackend>(backend: &B, params: &Value) -> Result<Value, RpcError> {
    let (addr, slots, block) = parse_get_proof_params(params)?;
    let proof = backend.eth_get_proof(&addr, &slots, block)?;
    Ok(serialize_proof(&proof))
}

fn parse_log_filter(params: &Value) -> Result<crate::backend::EthLogFilter, RpcError> {
    use crate::backend::EthLogFilter;

    let obj = params
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_object())
        .ok_or_else(|| RpcError::InvalidParams("expected [filter_object]".into()))?;

    let from_block = parse_block_tag(obj.get("fromBlock"))?;
    let to_block = parse_block_tag(obj.get("toBlock"))?;

    let block_hash = match obj.get("blockHash").and_then(|v| v.as_str()) {
        Some(s) => Some(
            Hash32::from_hex(s)
                .map_err(|e| RpcError::InvalidParams(format!("bad blockHash: {e}")))?,
        ),
        None => None,
    };

    // `address` : string OU array de strings.
    let mut addresses = Vec::new();
    if let Some(addr_val) = obj.get("address") {
        if let Some(s) = addr_val.as_str() {
            addresses.push(
                EvmAddress::from_hex(s)
                    .map_err(|e| RpcError::InvalidParams(format!("bad address: {e}")))?,
            );
        } else if let Some(arr) = addr_val.as_array() {
            for (i, v) in arr.iter().enumerate() {
                let s = v
                    .as_str()
                    .ok_or_else(|| RpcError::InvalidParams(format!("address[{i}] not a string")))?;
                addresses.push(
                    EvmAddress::from_hex(s)
                        .map_err(|e| RpcError::InvalidParams(format!("bad address[{i}]: {e}")))?,
                );
            }
        } else {
            return Err(RpcError::InvalidParams(
                "address must be a string or array".into(),
            ));
        }
    }

    // `topics` : array de (null | hash | array de hashes).
    let mut topics = Vec::new();
    if let Some(topic_val) = obj.get("topics") {
        let arr = topic_val
            .as_array()
            .ok_or_else(|| RpcError::InvalidParams("topics must be an array".into()))?;
        for (i, v) in arr.iter().enumerate() {
            if v.is_null() {
                topics.push(None);
            } else if let Some(s) = v.as_str() {
                let h = Hash32::from_hex(s)
                    .map_err(|e| RpcError::InvalidParams(format!("bad topic[{i}]: {e}")))?;
                topics.push(Some(vec![h]));
            } else if let Some(sub) = v.as_array() {
                let mut hashes = Vec::with_capacity(sub.len());
                for (j, h) in sub.iter().enumerate() {
                    let s = h.as_str().ok_or_else(|| {
                        RpcError::InvalidParams(format!("topic[{i}][{j}] not a string"))
                    })?;
                    hashes.push(Hash32::from_hex(s).map_err(|e| {
                        RpcError::InvalidParams(format!("bad topic[{i}][{j}]: {e}"))
                    })?);
                }
                topics.push(Some(hashes));
            } else {
                return Err(RpcError::InvalidParams(format!(
                    "topic[{i}] must be null, string, or array of strings"
                )));
            }
        }
    }

    Ok(EthLogFilter {
        from_block,
        to_block,
        block_hash,
        addresses,
        topics,
    })
}

fn parse_block_tag(v: Option<&Value>) -> Result<Option<crate::backend::BlockTag>, RpcError> {
    use crate::backend::BlockTag;
    let Some(v) = v else {
        return Ok(None);
    };
    if v.is_null() {
        return Ok(None);
    }
    let s = v
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("block tag must be a string".into()))?;
    Ok(Some(match s {
        "latest" => BlockTag::Latest,
        "earliest" => BlockTag::Earliest,
        "pending" => BlockTag::Pending,
        // Alias pour clients modernes : on retombe sur latest.
        "safe" | "finalized" => BlockTag::Latest,
        _ => {
            let n = parse_u64_hex(s)
                .map_err(|e| RpcError::InvalidParams(format!("bad block tag `{s}`: {e}")))?;
            BlockTag::Number(n)
        }
    }))
}

fn parse_get_proof_params(
    params: &Value,
) -> Result<(EvmAddress, Vec<U256>, Option<u64>), RpcError> {
    let arr = params.as_array().ok_or_else(|| {
        RpcError::InvalidParams("expected [address, storage_keys, block?]".into())
    })?;

    let addr_str = arr
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::InvalidParams("missing or bad address".into()))?;
    let addr = EvmAddress::from_hex(addr_str)
        .map_err(|e| RpcError::InvalidParams(format!("bad address: {e}")))?;

    let keys_arr = arr
        .get(1)
        .and_then(|v| v.as_array())
        .ok_or_else(|| RpcError::InvalidParams("missing or bad storage_keys array".into()))?;
    let mut slots = Vec::with_capacity(keys_arr.len());
    for (i, v) in keys_arr.iter().enumerate() {
        let s = v
            .as_str()
            .ok_or_else(|| RpcError::InvalidParams(format!("storage_keys[{i}] not a string")))?;
        let u = parse_u256_hex(s)
            .map_err(|e| RpcError::InvalidParams(format!("bad storage_keys[{i}]: {e}")))?;
        slots.push(u);
    }

    // 3ᵉ paramètre optionnel : blockNumber. On l'accepte mais l'implémenteur
    // décidera s'il peut le traiter (V1 : tip uniquement).
    let block = arr
        .get(2)
        .and_then(|v| v.as_str().and_then(|s| parse_u64_hex(s).ok()));

    Ok((addr, slots, block))
}

fn serialize_logs(logs: &[crate::backend::EthLog]) -> Value {
    let arr: Vec<Value> = logs
        .iter()
        .map(|l| {
            json!({
                "address": format!("0x{}", l.address.to_hex()),
                "topics": l
                    .topics
                    .iter()
                    .map(|t| format!("0x{}", t.to_hex()))
                    .collect::<Vec<_>>(),
                "data": format!("0x{}", hex::encode(&l.data)),
                "blockNumber": format!("0x{:x}", l.block_number),
                "blockHash": format!("0x{}", l.block_hash.to_hex()),
                "transactionHash": format!("0x{}", l.transaction_hash.to_hex()),
                "transactionIndex": format!("0x{:x}", l.transaction_index),
                "logIndex": format!("0x{:x}", l.log_index),
                "removed": l.removed,
            })
        })
        .collect();
    Value::Array(arr)
}

fn serialize_proof(p: &crate::backend::EthProof) -> Value {
    json!({
        "address": format!("0x{}", p.address.to_hex()),
        "accountProof": p
            .account_proof
            .iter()
            .map(|n| format!("0x{}", hex::encode(n)))
            .collect::<Vec<_>>(),
        "balance": format!("0x{:x}", p.balance),
        "codeHash": format!("0x{}", p.code_hash.to_hex()),
        "nonce": format!("0x{:x}", p.nonce),
        "storageHash": format!("0x{}", p.storage_hash.to_hex()),
        "storageProof": p
            .storage_proof
            .iter()
            .map(|sp| {
                json!({
                    "key": format!("0x{:x}", sp.key),
                    "value": format!("0x{:x}", sp.value),
                    "proof": sp
                        .proof
                        .iter()
                        .map(|n| format!("0x{}", hex::encode(n)))
                        .collect::<Vec<_>>(),
                })
            })
            .collect::<Vec<_>>(),
    })
}

// --- Batch dispatch --------------------------------------------------------

/// Dispatch un corps JSON arbitraire : objet unique ou tableau batch.
///
/// ## Règles JSON-RPC 2.0
///
/// - Objet → une réponse unique.
/// - Tableau non vide → tableau de réponses (une par item, dans l'ordre).
/// - Tableau vide → erreur unique `-32600` (`id: null`).
/// - Autre (nombre, string, …) → erreur unique `-32600`.
pub fn dispatch_value<B: RpcBackend>(backend: &B, value: Value) -> Value {
    match value {
        Value::Array(items) => {
            if items.is_empty() {
                return json!({
                    "jsonrpc": "2.0",
                    "error": { "code": -32600, "message": "empty batch request" },
                    "id": Value::Null,
                });
            }
            let responses: Vec<Value> = items
                .into_iter()
                .map(|item| dispatch_single_value(backend, item))
                .collect();
            Value::Array(responses)
        }
        other => dispatch_single_value(backend, other),
    }
}

fn dispatch_single_value<B: RpcBackend>(backend: &B, value: Value) -> Value {
    let req: Request = match serde_json::from_value(value) {
        Ok(r) => r,
        Err(e) => {
            return json!({
                "jsonrpc": "2.0",
                "error": {
                    "code": -32600,
                    "message": format!("invalid request: {e}")
                },
                "id": Value::Null,
            });
        }
    };
    let resp = dispatch(backend, req);
    // `Response` n'a pas de `Deserialize` mais dérive `Serialize`.
    serde_json::to_value(&resp).unwrap_or(Value::Null)
}

// --- Helpers ---------------------------------------------------------------

fn parse_u64_param(params: &Value, index: usize, name: &str) -> Result<u64, RpcError> {
    let v = params
        .as_array()
        .and_then(|a| a.get(index))
        .ok_or_else(|| RpcError::InvalidParams(format!("missing param {name}")))?;
    if let Some(n) = v.as_u64() {
        return Ok(n);
    }
    if let Some(s) = v.as_str() {
        if let Some(stripped) = s.strip_prefix("0x") {
            return u64::from_str_radix(stripped, 16)
                .map_err(|e| RpcError::InvalidParams(format!("bad hex {name}: {e}")));
        }
        return s
            .parse()
            .map_err(|e| RpcError::InvalidParams(format!("bad {name}: {e}")));
    }
    Err(RpcError::InvalidParams(format!("bad type for {name}")))
}

fn parse_address_param(
    params: &Value,
    index: usize,
    name: &str,
) -> Result<NativeAddress, RpcError> {
    let s = params
        .as_array()
        .and_then(|a| a.get(index))
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::InvalidParams(format!("missing param {name}")))?;
    NativeAddress::from_hex(s).map_err(|e| RpcError::InvalidParams(format!("bad {name}: {e}")))
}

fn parse_evm_address_param(
    params: &Value,
    index: usize,
    name: &str,
) -> Result<EvmAddress, RpcError> {
    let s = params
        .as_array()
        .and_then(|a| a.get(index))
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::InvalidParams(format!("missing param {name}")))?;
    EvmAddress::from_hex(s).map_err(|e| RpcError::InvalidParams(format!("bad {name}: {e}")))
}

fn parse_u256_param(params: &Value, index: usize, name: &str) -> Result<U256, RpcError> {
    let s = params
        .as_array()
        .and_then(|a| a.get(index))
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::InvalidParams(format!("missing param {name}")))?;
    parse_u256_hex(s).map_err(|e| RpcError::InvalidParams(format!("bad {name}: {e}")))
}

fn parse_u256_hex(s: &str) -> Result<U256, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let padded = if s.len() % 2 == 1 {
        format!("0{s}")
    } else {
        s.to_string()
    };
    let bytes = hex::decode(&padded).map_err(|e| format!("bad hex: {e}"))?;
    if bytes.len() > 32 {
        return Err(format!("u256 overflow: {} bytes", bytes.len()));
    }
    let mut buf = [0u8; 32];
    buf[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(U256::from_be_bytes::<32>(buf))
}

fn decode_hex(s: &str) -> Result<Vec<u8>, RpcError> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(stripped).map_err(|e| RpcError::InvalidParams(format!("bad hex: {e}")))
}

/// Parse l'objet `{from, to, gas, gasPrice, value, data}` de `eth_call`.
fn parse_eth_call_request(params: &Value) -> Result<EthCallRequest, RpcError> {
    let obj = params
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_object())
        .ok_or_else(|| RpcError::InvalidParams("expected [call_object]".into()))?;

    let from = match obj.get("from").and_then(|v| v.as_str()) {
        Some(s) => EvmAddress::from_hex(s)
            .map_err(|e| RpcError::InvalidParams(format!("bad from: {e}")))?,
        None => EvmAddress::ZERO,
    };
    let to = match obj.get("to").and_then(|v| v.as_str()) {
        Some(s) => Some(
            EvmAddress::from_hex(s).map_err(|e| RpcError::InvalidParams(format!("bad to: {e}")))?,
        ),
        None => None,
    };
    let gas = match obj.get("gas").and_then(|v| v.as_str()) {
        Some(s) => {
            Some(parse_u64_hex(s).map_err(|e| RpcError::InvalidParams(format!("bad gas: {e}")))?)
        }
        None => None,
    };
    let gas_price = match obj.get("gasPrice").and_then(|v| v.as_str()) {
        Some(s) => Some(
            parse_u256_hex(s).map_err(|e| RpcError::InvalidParams(format!("bad gasPrice: {e}")))?,
        ),
        None => None,
    };
    let value = match obj.get("value").and_then(|v| v.as_str()) {
        Some(s) => {
            parse_u256_hex(s).map_err(|e| RpcError::InvalidParams(format!("bad value: {e}")))?
        }
        None => U256::ZERO,
    };
    // `data` et `input` sont synonymes (EIP-1474).
    let data = match obj
        .get("data")
        .or_else(|| obj.get("input"))
        .and_then(|v| v.as_str())
    {
        Some(s) => decode_hex(s)?,
        None => Vec::new(),
    };

    Ok(EthCallRequest {
        from,
        to,
        gas,
        gas_price,
        value,
        data,
    })
}

fn parse_u64_hex(s: &str) -> Result<u64, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(s, 16).map_err(|e| format!("bad u64 hex: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sango_primitives::{Amount, ChainId32, Hash32};
    use serde_json::json;

    // --- Backend fictif : implémentation minimale pour tester le dispatch.

    struct MockBackend {
        chain_id: ChainId32,
        block_number: Option<u64>,
        eth_chain_id: u64,
        eth_gas_price: U256,
        balance: U256,
        nonce: u64,
        code: Vec<u8>,
        storage: U256,
        call_output: Vec<u8>,
        call_gas: u64,
    }

    impl Default for MockBackend {
        fn default() -> Self {
            Self {
                chain_id: ChainId32::from_bytes([0x11; 32]),
                block_number: None,
                eth_chain_id: 7777,
                eth_gas_price: U256::from(7u64),
                balance: U256::from(1_000_000u64),
                nonce: 42,
                code: vec![0x60, 0x01],
                storage: U256::from(0xabcu64),
                call_output: vec![0xde, 0xad],
                call_gas: 21_000,
            }
        }
    }

    impl RpcBackend for MockBackend {
        fn chain_id(&self) -> ChainId32 {
            self.chain_id
        }
        fn block_number(&self) -> Option<u64> {
            self.block_number
        }
        fn get_block_by_height(&self, _: u64) -> Option<sango_types::Block> {
            None
        }
        fn get_account(&self, _: &NativeAddress) -> Option<sango_types::NativeAccount> {
            None
        }
        fn get_balance(&self, _: &NativeAddress) -> Amount {
            Amount::ZERO
        }
        fn get_validators(&self) -> Vec<sango_types::ValidatorInfo> {
            Vec::new()
        }
        fn send_transaction(&self, _: &Transaction) -> Result<Hash32, RpcError> {
            Err(RpcError::Internal("not used".into()))
        }

        fn eth_chain_id(&self) -> u64 {
            self.eth_chain_id
        }
        fn eth_gas_price(&self) -> U256 {
            self.eth_gas_price
        }
        fn eth_get_balance(&self, _: &EvmAddress) -> U256 {
            self.balance
        }
        fn eth_get_transaction_count(&self, _: &EvmAddress) -> u64 {
            self.nonce
        }
        fn eth_get_code(&self, _: &EvmAddress) -> Vec<u8> {
            self.code.clone()
        }
        fn eth_get_storage_at(&self, _: &EvmAddress, _: U256) -> U256 {
            self.storage
        }
        fn eth_call(&self, _: &EthCallRequest) -> Result<crate::backend::EthCallResult, RpcError> {
            Ok(crate::backend::EthCallResult {
                success: true,
                output: self.call_output.clone(),
                gas_used: self.call_gas,
            })
        }
        fn eth_estimate_gas(&self, _: &EthCallRequest) -> Result<u64, RpcError> {
            Ok(self.call_gas)
        }
        fn eth_send_raw_transaction(&self, _raw: &[u8]) -> Result<Hash32, RpcError> {
            // Mock : retourne un hash constant.
            Ok(Hash32::from_bytes([0xab; 32]))
        }
        fn eth_get_logs(
            &self,
            _filter: &crate::backend::EthLogFilter,
        ) -> Result<Vec<crate::backend::EthLog>, RpcError> {
            // Mock : 1 log constant.
            Ok(vec![crate::backend::EthLog {
                address: EvmAddress::from_bytes([0xaa; 20]),
                topics: vec![Hash32::from_bytes([0x11; 32])],
                data: vec![0xde, 0xad],
                block_number: 5,
                block_hash: Hash32::from_bytes([0x55; 32]),
                transaction_hash: Hash32::from_bytes([0x66; 32]),
                transaction_index: 0,
                log_index: 0,
                removed: false,
            }])
        }
        fn eth_get_proof(
            &self,
            address: &EvmAddress,
            storage_keys: &[U256],
            _block: Option<u64>,
        ) -> Result<crate::backend::EthProof, RpcError> {
            let storage_proof = storage_keys
                .iter()
                .map(|k| crate::backend::EthStorageProof {
                    key: *k,
                    value: U256::from(0xbeef_u64),
                    proof: vec![vec![0x01, 0x02]],
                })
                .collect();
            Ok(crate::backend::EthProof {
                address: *address,
                account_proof: vec![vec![0x0a, 0x0b]],
                balance: U256::from(1000u64),
                code_hash: Hash32::from_bytes([0xcc; 32]),
                nonce: 42,
                storage_hash: Hash32::from_bytes([0xdd; 32]),
                storage_proof,
            })
        }
    }

    fn call<B: RpcBackend>(backend: &B, method: &str, params: Value) -> Value {
        let req = Request {
            jsonrpc: "2.0".into(),
            method: method.into(),
            params,
            id: json!(1),
        };
        let resp = dispatch(backend, req);
        resp.result.unwrap_or(Value::Null)
    }

    // --- Tests natives (conservés) ---------------------------------------

    #[test]
    fn sango_chain_id_returns_hex() {
        let b = MockBackend::default();
        let v = call(&b, "sango_chainId", json!([]));
        assert_eq!(v, json!(format!("0x{}", "11".repeat(32))));
    }

    // --- Tests EVM -------------------------------------------------------

    #[test]
    fn eth_chain_id_hex() {
        let b = MockBackend::default();
        assert_eq!(call(&b, "eth_chainId", json!([])), json!("0x1e61")); // 7777
    }

    #[test]
    fn eth_block_number_zero_when_none() {
        let b = MockBackend::default();
        assert_eq!(call(&b, "eth_blockNumber", json!([])), json!("0x0"));
    }

    #[test]
    fn eth_gas_price_hex() {
        let b = MockBackend::default();
        assert_eq!(call(&b, "eth_gasPrice", json!([])), json!("0x7"));
    }

    #[test]
    fn eth_get_balance_hex() {
        let b = MockBackend::default();
        let v = call(
            &b,
            "eth_getBalance",
            json!(["0x0000000000000000000000000000000000000001", "latest"]),
        );
        assert_eq!(v, json!("0xf4240")); // 1_000_000
    }

    #[test]
    fn eth_get_transaction_count_hex() {
        let b = MockBackend::default();
        let v = call(
            &b,
            "eth_getTransactionCount",
            json!(["0x0000000000000000000000000000000000000001", "latest"]),
        );
        assert_eq!(v, json!("0x2a")); // 42
    }

    #[test]
    fn eth_get_code_hex() {
        let b = MockBackend::default();
        let v = call(
            &b,
            "eth_getCode",
            json!(["0x0000000000000000000000000000000000000001", "latest"]),
        );
        assert_eq!(v, json!("0x6001"));
    }

    #[test]
    fn eth_get_storage_at_32_bytes() {
        let b = MockBackend::default();
        let v = call(
            &b,
            "eth_getStorageAt",
            json!([
                "0x0000000000000000000000000000000000000001",
                "0x0",
                "latest"
            ]),
        );
        let s = v.as_str().unwrap();
        assert_eq!(s.len(), 66); // 0x + 64 hex
        assert!(s.starts_with("0x"));
        assert!(s.ends_with("abc"));
    }

    #[test]
    fn eth_call_returns_output() {
        let b = MockBackend::default();
        let v = call(
            &b,
            "eth_call",
            json!([
                {
                    "from": "0x0000000000000000000000000000000000000001",
                    "to": "0x0000000000000000000000000000000000000002",
                    "data": "0x"
                },
                "latest"
            ]),
        );
        assert_eq!(v, json!("0xdead"));
    }

    #[test]
    fn eth_estimate_gas_hex() {
        let b = MockBackend::default();
        let v = call(
            &b,
            "eth_estimateGas",
            json!([
                {
                    "from": "0x0000000000000000000000000000000000000001",
                    "to": "0x0000000000000000000000000000000000000002",
                    "data": "0x"
                }
            ]),
        );
        assert_eq!(v, json!("0x5208")); // 21_000
    }

    #[test]
    fn eth_call_with_data_and_value() {
        let b = MockBackend::default();
        // Vérifie que le parsing ne rejette pas data ni value.
        let v = call(
            &b,
            "eth_call",
            json!([
                {
                    "from": "0x0000000000000000000000000000000000000001",
                    "to": "0x0000000000000000000000000000000000000002",
                    "data": "0x1234",
                    "value": "0xff"
                },
                "latest"
            ]),
        );
        assert_eq!(v, json!("0xdead"));
    }

    #[test]
    fn eth_send_raw_transaction_routes_and_returns_hash() {
        let b = MockBackend::default();
        let v = call(&b, "eth_sendRawTransaction", json!(["0xdeadbeef"]));
        assert_eq!(v, json!(format!("0x{}", "ab".repeat(32))));
    }

    #[test]
    fn eth_get_logs_routes_and_returns_logs() {
        let b = MockBackend::default();
        let v = call(
            &b,
            "eth_getLogs",
            json!([{
                "fromBlock": "0x0",
                "toBlock": "0x5",
                "address": "0x000000000000000000000000000000000000aaaa"
            }]),
        );
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(
            arr[0].get("address").and_then(|x| x.as_str()),
            Some("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        assert_eq!(
            arr[0].get("blockNumber").and_then(|x| x.as_str()),
            Some("0x5")
        );
        assert_eq!(arr[0].get("logIndex").and_then(|x| x.as_str()), Some("0x0"));
        assert_eq!(arr[0].get("removed").and_then(|x| x.as_bool()), Some(false));
    }

    #[test]
    fn eth_get_logs_accepts_latest_tag() {
        let b = MockBackend::default();
        let v = call(&b, "eth_getLogs", json!([{ "fromBlock": "latest" }]));
        assert!(v.is_array());
    }

    #[test]
    fn eth_get_logs_rejects_bad_address() {
        let b = MockBackend::default();
        let req = Request {
            jsonrpc: "2.0".into(),
            method: "eth_getLogs".into(),
            params: json!([{ "address": "0xnot-hex" }]),
            id: json!(1),
        };
        let resp = dispatch(&b, req);
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32602);
    }

    #[test]
    fn eth_get_logs_accepts_array_of_addresses_and_topics() {
        let b = MockBackend::default();
        let v = call(
            &b,
            "eth_getLogs",
            json!([{
                "address": [
                    "0x0000000000000000000000000000000000000001",
                    "0x0000000000000000000000000000000000000002"
                ],
                "topics": [
                    "0x0000000000000000000000000000000000000000000000000000000000000011",
                    null,
                    ["0x0000000000000000000000000000000000000000000000000000000000000022"]
                ]
            }]),
        );
        assert!(v.is_array());
    }

    #[test]
    fn eth_get_proof_routes_and_returns_proof() {
        let b = MockBackend::default();
        let v = call(
            &b,
            "eth_getProof",
            json!([
                "0x0000000000000000000000000000000000000001",
                ["0x0000000000000000000000000000000000000000000000000000000000000007"],
                "latest"
            ]),
        );
        assert_eq!(v.get("address").and_then(|x| x.as_str()).unwrap().len(), 42);
        assert_eq!(v.get("balance").and_then(|x| x.as_str()), Some("0x3e8"));
        assert_eq!(v.get("nonce").and_then(|x| x.as_str()), Some("0x2a"));
        let sp = v.get("storageProof").and_then(|x| x.as_array()).unwrap();
        assert_eq!(sp.len(), 1);
        assert_eq!(sp[0].get("value").and_then(|x| x.as_str()), Some("0xbeef"));
    }

    #[test]
    fn eth_get_proof_rejects_bad_params() {
        let b = MockBackend::default();
        let req = Request {
            jsonrpc: "2.0".into(),
            method: "eth_getProof".into(),
            params: json!(["0xnot-hex", []]),
            id: json!(1),
        };
        let resp = dispatch(&b, req);
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32602);
    }

    // --- Batch dispatch ---------------------------------------------------

    #[test]
    fn batch_with_two_valid_requests() {
        let b = MockBackend::default();
        let body = json!([
            {"jsonrpc": "2.0", "method": "eth_chainId", "params": [], "id": 1},
            {"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 2},
        ]);
        let resp = super::dispatch_value(&b, body);
        let arr = resp.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(
            arr[0].get("result").and_then(|x| x.as_str()),
            Some("0x1e61")
        );
        assert_eq!(arr[0].get("id").and_then(|x| x.as_u64()), Some(1));
        assert_eq!(arr[1].get("result").and_then(|x| x.as_str()), Some("0x0"));
        assert_eq!(arr[1].get("id").and_then(|x| x.as_u64()), Some(2));
    }

    #[test]
    fn batch_with_one_invalid_item_returns_ordered_errors() {
        let b = MockBackend::default();
        let body = json!([
            {"jsonrpc": "2.0", "method": "eth_chainId", "params": [], "id": 1},
            {"jsonrpc": "2.0", "method": "eth_doesNotExist", "params": [], "id": 2},
            {"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 3},
        ]);
        let resp = super::dispatch_value(&b, body);
        let arr = resp.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert!(arr[0].get("result").is_some());
        assert!(arr[1].get("error").is_some());
        assert!(arr[2].get("result").is_some());
    }

    #[test]
    fn empty_batch_returns_single_error() {
        let b = MockBackend::default();
        let resp = super::dispatch_value(&b, json!([]));
        assert!(resp.is_object());
        assert!(resp.get("error").is_some());
    }

    #[test]
    fn batch_with_non_object_item_returns_error_for_that_item() {
        let b = MockBackend::default();
        let resp = super::dispatch_value(&b, json!(["not an object"]));
        let arr = resp.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert!(arr[0].get("error").is_some());
    }

    #[test]
    fn non_object_non_array_body_returns_error() {
        let b = MockBackend::default();
        let resp = super::dispatch_value(&b, json!("hello"));
        assert!(resp.is_object());
        assert!(resp.get("error").is_some());
    }

    #[test]
    fn unknown_method_rejected() {
        let b = MockBackend::default();
        let req = Request {
            jsonrpc: "2.0".into(),
            method: "eth_doesNotExist".into(),
            params: json!([]),
            id: json!(1),
        };
        let resp = dispatch(&b, req);
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32601);
    }

    // Marqueur anti-warning.
    #[allow(dead_code)]
    fn _marker(_: Hash32, _: Amount) {}
}
