
RPC JSON-RPC — référence

Le nœud expose un serveur JSON-RPC 2.0 sur http://127.0.0.1:8545/rpc
par défaut.
Transport

    HTTP/1.1 (pas HTTP/2).

    POST uniquement pour les méthodes (sauf OPTIONS preflight).

    Content-Type: application/json.

    Keep-alive supporté (défaut HTTP/1.1).

    Batch supporté (tableau JSON).

    CORS : Access-Control-Allow-Origin: * + preflight OPTIONS → 204.

Exemple de requête :
bash

curl -s -X POST http://127.0.0.1:8545/rpc \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"sango_blockNumber","params":[],"id":1}'

Réponse :
json

{ "jsonrpc": "2.0", "result": 42, "id": 1 }

Erreur :
json

{ "jsonrpc": "2.0", "error": { "code": -32601, "message": "method not found: foo" }, "id": 1 }

Codes standards :

    -32700 parse error

    -32600 invalid request

    -32601 method not found

    -32602 invalid params

    -32603 internal error

    -32001 not found (extension Sango)

    -32010 transaction rejected (extension Sango)

Conventions de typage

    Montants (Amount) : string décimale en base units.
    1 SANGO = "10000000".

    Hauteurs, nonces, index (u64, u32) : number JSON.

    Hashs, adresses, bytes : string hex 0x….

    Option nulle : null.

Namespace sango_* — natif
sango_chainId
json

{ "method": "sango_chainId", "params": [] }
→ "0x1111…"   // 32 bytes hex

sango_blockNumber
json

{ "method": "sango_blockNumber", "params": [] }
→ 42          // u64, ou null si aucun bloc

sango_chainInfo
json

{ "method": "sango_chainInfo", "params": [] }
→ {
    "chainId": "0x…",
    "height": 42,
    "validatorCount": 4,
    "protocolVersion": 1
  }

sango_baseFee

Base fee courante (base units par gas), calculée EIP-1559.
json

{ "method": "sango_baseFee", "params": [] }
→ "1"

Recommandation de signature côté client : max_fee = base_fee * 2.
sango_getBlock
json

{ "method": "sango_getBlock", "params": [42] }
→ {
    "height": 42,
    "hash": "0x…",
    "bytes": "0x…"     // bloc complet encodé (sango-codec)
  }
→ null si absent

sango_getAccount
json

{ "method": "sango_getAccount", "params": ["0x<40 hex>"] }
→ {
    "address": "0x…",
    "publicKey": "0x…" | null,    // null si compte fantôme
    "balance": "1000000000",
    "nonce": 42
  }
→ null si absent

sango_getBalance
json

{ "method": "sango_getBalance", "params": ["0x<40 hex>"] }
→ "1000000000"

Retourne "0" si le compte n'existe pas.
sango_getValidators
json

{ "method": "sango_getValidators", "params": [] }
→ [ ValidatorInfo, … ]

ValidatorInfo :
json

{
  "address": "0x<40 hex>",
  "publicKey": "0x<64 hex>",
  "selfStake": "1000000000000",
  "totalDelegated": "0",
  "votingPower": "1000000000000",
  "commissionBps": 700,
  "jailed": false,
  "pendingCommissionBps": null,
  "pendingCommissionAt": null,
  "jailedUntil": null,
  "downtimeWindowStart": 0,
  "downtimeMissed": 0
}

sango_getValidatorInfo
json

{ "method": "sango_getValidatorInfo", "params": ["0x<40 hex>"] }
→ ValidatorInfo | null

sango_getDelegations

Toutes les délégations émises par une adresse.
json

{ "method": "sango_getDelegations", "params": ["0x<40 hex>"] }
→ [
    {
      "delegator": "0x…",
      "validator": "0x…",
      "bonded": "…",
      "unbonding": "…",
      "unbondingUntil": null | number,
      "pendingRewards": "…"
    }
  ]

sango_getPendingUnbondings
json

{ "method": "sango_getPendingUnbondings", "params": ["0x<40 hex>"] }
→ [
    {
      "id": 0,
      "delegator": "0x…",
      "validator": "0x…",
      "amount": "…",
      "matureAt": 1234567890
    }
  ]

sango_sendTransaction

Envoie une transaction native (déjà signée Ed25519).
json

{ "method": "sango_sendTransaction", "params": ["0x<tx_bytes>"] }
→ "0x<hash>"

L'argument est l'encodage canonique sango-codec de la tx complète
(y compris la signature). Voir Transaction::encode_to_vec côté Rust, ou
la sortie sango-wallet send --emit-raw.
sango_getTransactionByHash
json

{ "method": "sango_getTransactionByHash", "params": ["0x<64 hex>"] }
→ {
    "hash": "0x…",
    "blockHeight": 42,
    "blockHash": "0x…",
    "txIndex": 0,
    "kind": "native" | "evm",
    "txKind": 1 | null,        // TxKind natif 1..11, null pour EVM
    "tx": "0x<tx_bytes>"       // bytes canoniques (native: sango-codec,
                               //                    evm: ethereum_typed)
  }
→ null si inconnue

sango_getTransactionsByAddress
json

{ "method": "sango_getTransactionsByAddress", "params": ["0x<40 hex>", 20, 0] }
→ {
    "total": 42,
    "offset": 0,
    "limit": 20,
    "items": [ /* même format que sango_getTransactionByHash */ ]
  }

    limit : défaut 20, max 100 (cap silencieux).

    offset : défaut 0.

    Ordre : plus récentes d'abord.

    Natives uniquement en V1 (les EVM utilisent eth_*).

Namespace eth_* — EVM-compatible

Ces méthodes suivent le standard Ethereum (EIP-1474 / EIP-1898). Elles
n'exposent que les txs EVM ; les txs natives renvoient null.
eth_chainId
json

{ "method": "eth_chainId", "params": [] }
→ "0x53414e474f"   // 357915159887

eth_blockNumber
json

→ "0x2a"

eth_gasPrice
json

→ "0x1"

eth_getBalance
json

{ "method": "eth_getBalance", "params": ["0x…", "latest"] }
→ "0x…"   // solde EVM hexadécimal

eth_getTransactionCount
json

{ "method": "eth_getTransactionCount", "params": ["0x…", "latest"] }
→ "0x…"   // nonce EVM

eth_getCode
json

{ "method": "eth_getCode", "params": ["0x…", "latest"] }
→ "0x…"   // bytecode

eth_getStorageAt
json

{ "method": "eth_getStorageAt", "params": ["0x…", "0x0", "latest"] }
→ "0x" + 64 hex

eth_call

Exécution read-only d'un appel EVM.
json

{ "method": "eth_call", "params": [
    { "from": "0x…", "to": "0x…", "data": "0x…", "value": "0x0", "gas": "0x…", "gasPrice": "0x…" },
    "latest"
  ] }
→ "0x<output>"

eth_estimateGas
json

{ "method": "eth_estimateGas", "params": [{ "from": "0x…", "to": "0x…", "data": "0x…" }] }
→ "0x5208"

eth_sendRawTransaction

Envoie une typed-transaction Ethereum signée secp256k1.
json

{ "method": "eth_sendRawTransaction", "params": ["0x<raw>"] }
→ "0x<hash>"

Types supportés : 0x00 (Legacy), 0x01 (EIP-2930), 0x02 (EIP-1559),
0x04 (EIP-7702). Le type 0x03 (blob) est rejeté.
eth_getLogs
json

{ "method": "eth_getLogs", "params": [{
    "fromBlock": "0x0",
    "toBlock": "latest",
    "address": "0x…" | ["0x…"],
    "topics": ["0x…", null, ["0x…"]]
  }] }
→ [ Log, … ]

Log :
json

{
  "address": "0x…",
  "topics": ["0x…", …],
  "data": "0x…",
  "blockNumber": "0x…",
  "blockHash": "0x…",
  "transactionHash": "0x…",
  "transactionIndex": "0x…",
  "logIndex": "0x…",
  "removed": false
}

eth_getProof

Preuve MPT EIP-1186.
json

{ "method": "eth_getProof", "params": ["0x…", ["0x0", "0x1"], "latest"] }
→ {
    "address": "0x…",
    "accountProof": ["0x…", …],
    "balance": "0x…",
    "codeHash": "0x…",
    "nonce": "0x…",
    "storageHash": "0x…",
    "storageProof": [
      { "key": "0x…", "value": "0x…", "proof": ["0x…", …] }
    ]
  }

eth_getTransactionByHash
json

{ "method": "eth_getTransactionByHash", "params": ["0x<64 hex>"] }
→ {
    "hash": "0x…",
    "blockHash": "0x…",
    "blockNumber": "0x…",
    "transactionIndex": "0x…",
    "from": "0x…",
    "to": "0x…" | null,
    "value": "0x…",
    "gas": "0x…",
    "input": "0x…",
    "nonce": "0x…",
    "type": "0x…",
    "chainId": "0x…",
    "gasPrice" | "maxFeePerGas"/"maxPriorityFeePerGas": "0x…",
    "accessList"?: [ … ],
    "v": "0x…",
    "r": "0x…",
    "s": "0x…"
  }
→ null si tx inconnue OU native

eth_getTransactionReceipt
json

{ "method": "eth_getTransactionReceipt", "params": ["0x<64 hex>"] }
→ {
    "transactionHash": "0x…",
    "transactionIndex": "0x…",
    "blockHash": "0x…",
    "blockNumber": "0x…",
    "from": "0x…",
    "to": "0x…" | null,
    "cumulativeGasUsed": "0x…",
    "gasUsed": "0x…",
    "contractAddress": "0x…" | null,
    "logs": [ … ],
    "logsBloom": "0x…",
    "status": "0x0" | "0x1",
    "type": "0x…"
  }
→ null si tx inconnue OU native

logIndex est global au bloc (conforme Ethereum).
eth_getBlockByNumber
json

{ "method": "eth_getBlockByNumber", "params": ["latest", false] }
→ {
    "number": "0x…",
    "hash": "0x…",
    "parentHash": "0x…",
    "nonce": "0x0000000000000000",
    "sha3Uncles": "0x1dcc4de8…",     // Keccak256(RLP([]))
    "logsBloom": "0x…",
    "transactionsRoot": "0x…",
    "stateRoot": "0x…",
    "receiptsRoot": "0x…",
    "miner": "0x0000000000000000000000000000000000000000",
    "difficulty": "0x0",
    "totalDifficulty": "0x0",
    "extraData": "0x",
    "size": "0x…",
    "gasLimit": "0x…",
    "gasUsed": "0x…",
    "timestamp": "0x…",
    "transactions": [ "0x…" ] | [ { tx }, … ],
    "uncles": [],
    "baseFeePerGas": "0x…"
  }
→ null si inconnu

transactions ne contient que les txs EVM. transactionIndex reste
l'index dans le bloc complet (gaps possibles si des txs natives sont
intercalées).
eth_getBlockByHash
json

{ "method": "eth_getBlockByHash", "params": ["0x<64 hex>", false] }
→ même format

Limites connues

    miner = adresse nulle (le proposeur Sango est une NativeAddress,
    sans correspondance EvmAddress).

    stateRoot / transactionsRoot / receiptsRoot sont MPT
    Ethereum-compatibles structurellement, mais les valeurs encodées
    sont Sango (pas RLP Ethereum). Ne pas tenter de vérifier ces roots avec
    un client Ethereum.

    Les méthodes eth_* n'exposent pas les txs natives.

    Le namespace eth_getLogs accepte fromBlock > toBlock → renvoie [].
    