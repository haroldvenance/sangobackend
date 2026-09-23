//! Dispatch JSON-RPC : méthode + params → résultat.

use serde_json::{json, Value};

use sango_codec::Decode as _;
use sango_primitives::{Amount, Hash32, NativeAddress};
use sango_types::Transaction;

use crate::backend::RpcBackend;
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
        "sango_chainId" => sango_chain_id(backend),
        "sango_blockNumber" => sango_block_number(backend),
        "sango_getBlock" => sango_get_block(backend, params),
        "sango_getAccount" => sango_get_account(backend, params),
        "sango_getBalance" => sango_get_balance(backend, params),
        "sango_getValidators" => sango_get_validators(backend),
        "sango_sendTransaction" => sango_send_transaction(backend, params),
        "sango_chainInfo" => sango_chain_info(backend),
        other => Err(RpcError::MethodNotFound(other.to_string())),
    }
}

// --- Méthodes --------------------------------------------------------------

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
        // Support "0x..." et décimal.
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

fn decode_hex(s: &str) -> Result<Vec<u8>, RpcError> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(stripped).map_err(|e| RpcError::InvalidParams(format!("bad hex: {e}")))
}

// Marqueur pour utiliser `Hash32` dans les conversions futures.
#[allow(dead_code)]
fn _marker(_: Hash32, _: Amount) {}
