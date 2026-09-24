//! Dispatch JSON-RPC : méthode + params → résultat.

use serde_json::{json, Value};

use sango_codec::Decode as _;
use sango_primitives::{EvmAddress, NativeAddress, U256};
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
