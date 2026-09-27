RPC — référence complète

Endpoint : POST http://127.0.0.1:8545/rpc (ou /).

Toutes les méthodes acceptent et retournent du JSON-RPC 2.0 :
json

{ "jsonrpc": "2.0", "method": "…", "params": […], "id": 1 }

Le serveur supporte le batch (tableau de requêtes), keep-alive,
et CORS (Access-Control-Allow-Origin: * + preflight OPTIONS).
Conventions

    Adresses natives : 0x + 40 hex (0x119a2d28…).

    Adresses EVM : 0x + 40 hex (même format, namespaces distincts).

    Hashes : 0x + 64 hex.

    Montants (Amount) : string décimale en base units (cohérent
    avec sango_getBalance). 1 SANGO = 10 000 000 base units (7
    décimales).

    Nombres : u64/u32 sont des number JSON (pas hex) côté
    sango_*. Côté eth_*, tout est hex préfixé 0x (spec Ethereum).

Méthodes sango_*
sango_chainId

Retourne le chain ID natif (32 bytes hex).
json

{ "method": "sango_chainId", "params": [] }
→ "0x1111111111111111111111111111111111111111111111111111111111111111"

sango_blockNumber

Retourne la hauteur du dernier bloc, ou null si aucun bloc.
json

{ "method": "sango_blockNumber", "params": [] }
→ 42

sango_getBlock
json

{ "method": "sango_getBlock", "params": [42] }
→ {
    "height": 42,
    "hash": "0x…",
    "bytes": "0x…"   // encodage canonique complet
  }
→ null si inconnu

sango_getAccount
json

{ "method": "sango_getAccount", "params": ["0x…"] }
→ {
    "address": "0x…",
    "publicKey": "0x…" | null,   // null si compte "fantôme"
    "balance": "12345678",        // base units, string décimale
    "nonce": 3
  }
→ null si compte absent

sango_getBalance
json

{ "method": "sango_getBalance", "params": ["0x…"] }
→ "12345678"    // base units, string décimale

sango_getValidators
json

{ "method": "sango_getValidators", "params": [] }
→ [
    {
      "address": "0x…",
      "publicKey": "0x…",
      "selfStake": "1000000000000",
      "totalDelegated": "0",
      "votingPower": "1000000000000",
      "commissionBps": 700,
      "jailed": false,
      "pendingCommissionBps": null | number,
      "pendingCommissionAt": null | number,
      "jailedUntil": null | number,
      "downtimeWindowStart": 0,
      "downtimeMissed": 0
    }
  ]

sango_chainInfo
json

{ "method": "sango_chainInfo", "params": [] }
→ {
    "chainId": "0x…",
    "height": 42,
    "validatorCount": 1,
    "protocolVersion": 1
  }

sango_baseFee
json

{ "method": "sango_baseFee", "params": [] }
→ "1000"    // base units par gas, string décimale

sango_sendTransaction

Soumet une transaction native signée (encodage canonique Sango, hex).
json

{ "method": "sango_sendTransaction", "params": ["0x<tx_bytes_hex>"] }
→ "0x<tx_hash>"
→ erreur -32010 si rejetée par le mempool

sango_getTransactionByHash
json

{ "method": "sango_getTransactionByHash", "params": ["0x<hash>"] }
→ {
    "hash": "0x…",
    "blockHeight": 42,
    "blockHash": "0x…",
    "txIndex": 0,
    "kind": "native",           // "native" | "evm"
    "txKind": 1,                 // TxKind natif 0x01..0x0B, null si EVM
    "tx": "0x<full_tx_bytes>"
  }
→ null si inconnue

tx est l'encodage canonique complet, même format que
sango_sendTransaction.
sango_getTransactionsByAddress

Pagination des txs natives envoyées par une adresse.
json

{ "method": "sango_getTransactionsByAddress",
  "params": ["0x…", 20, 0] }   // limit (défaut 20, max 100), offset (défaut 0)
→ {
    "total": 42,
    "offset": 0,
    "limit": 20,
    "items": [ /* même format que getTransactionByHash */ ]
  }

Ordre : plus récentes d'abord (décroissant par height, puis
txIndex).
sango_getValidatorInfo
json

{ "method": "sango_getValidatorInfo", "params": ["0x…"] }
→ <même objet que les éléments de sango_getValidators>
→ null si l'adresse n'est pas un validateur

sango_getDelegations

Liste les délégations émises par une adresse (délégateur).
json

{ "method": "sango_getDelegations", "params": ["0x…"] }
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

Liste les unbondings en attente de maturation pour une adresse.
json

{ "method": "sango_getPendingUnbondings", "params": ["0x…"] }
→ [
    {
      "id": 0,
      "delegator": "0x…",
      "validator": "0x…",
      "amount": "…",
      "matureAt": 1234567890
    }
  ]

Méthodes eth_* (Ethereum-compatibles)

Les méthodes eth_* exposent uniquement les txs EVM. Les txs
natives n'ont pas de représentation Ethereum ; utilise les sango_*
correspondantes.

Format des valeurs :

    U256 → hex 0x….

    u64 → hex 0x….

    Adresses et hashs → 0x + hex.

eth_chainId, eth_blockNumber, eth_gasPrice
json

{ "method": "eth_chainId", "params": [] } → "0x53414e474f"
{ "method": "eth_blockNumber", "params": [] } → "0x2a"
{ "method": "eth_gasPrice", "params": [] } → "0x…"

eth_getBalance, eth_getTransactionCount, eth_getCode
json

{ "method": "eth_getBalance", "params": ["0x…", "latest"] } → "0x…"
{ "method": "eth_getTransactionCount", "params": ["0x…", "latest"] } → "0x…"
{ "method": "eth_getCode", "params": ["0x…", "latest"] } → "0x…"

Le 2ᵉ paramètre (tag) est accepté mais ignoré en V1 : on interroge
toujours le tip.
eth_getStorageAt
json

{ "method": "eth_getStorageAt", "params": ["0x…", "0x0", "latest"] }
→ "0x<32 bytes hex>"

eth_call / eth_estimateGas
json

{ "method": "eth_call", "params": [
    {
      "from": "0x…",     // optionnel
      "to": "0x…",        // optionnel (None = création)
      "gas": "0x…",       // optionnel
      "gasPrice": "0x…",  // optionnel
      "value": "0x…",     // optionnel
      "data": "0x…"       // optionnel (alias "input" accepté)
    },
    "latest"
  ] }
→ "0x…"    // données de retour

eth_sendRawTransaction

Envoie une tx EVM signée (typed-transaction Ethereum 0x00…/0x01…/
0x02…/0x04…).
json

{ "method": "eth_sendRawTransaction", "params": ["0x<raw_hex>"] }
→ "0x<tx_hash>"
→ erreur -32010 si rejetée (nonce, balance, signature, chain_id)

Le sender est récupéré cryptographiquement de la signature ; il
n'est jamais fourni par l'appelant.
eth_getLogs
json

{ "method": "eth_getLogs", "params": [
    {
      "fromBlock": "0x0",           // optionnel
      "toBlock": "latest",           // optionnel
      "blockHash": "0x…",            // optionnel (override from/to)
      "address": "0x…" | ["0x…"],    // optionnel
      "topics": [                    // optionnel
        "0x…" | null | ["0x…", "0x…"]
      ]
    }
  ] }
→ [
    {
      "address": "0x…",
      "topics": ["0x…"],
      "data": "0x…",
      "blockNumber": "0x…",
      "blockHash": "0x…",
      "transactionHash": "0x…",
      "transactionIndex": "0x…",
      "logIndex": "0x…",
      "removed": false
    }
  ]

eth_getProof (EIP-1186)
json

{ "method": "eth_getProof",
  "params": ["0x…", ["0x…", "0x…"], "latest"] }
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

block (3ᵉ paramètre) est ignoré en V1 (tip uniquement).
eth_getTransactionByHash

Format EIP-1474. Champ from récupéré cryptographiquement.

    Legacy : type: "0x0", gasPrice, v, r, s.

    EIP-2930 : type: "0x1", gasPrice, accessList, v, r, s.

    EIP-1559 : type: "0x2", maxPriorityFeePerGas,
    maxFeePerGas, accessList, v, r, s.

    EIP-7702 : type: "0x4", idem 1559 + authorizationList.

Champs communs : hash, blockHash, blockNumber, transactionIndex,
from, to, value, gas, input, nonce, type.

null si inconnue ou si c'est une tx native.
eth_getTransactionReceipt
json

{ "method": "eth_getTransactionReceipt", "params": ["0x<hash>"] }
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
    "logs": [
      { "address", "topics", "data",
        "blockNumber", "transactionHash", "transactionIndex",
        "blockHash", "logIndex", "removed" }
    ],
    "logsBloom": "0x<256 bytes>",
    "status": "0x0" | "0x1",
    "type": "0x…"
  }
→ null si tx native ou inconnue

logIndex est global au bloc (Ethereum-compatible).
eth_getBlockByNumber / eth_getBlockByHash
json

{ "method": "eth_getBlockByNumber", "params": ["latest", false] }
{ "method": "eth_getBlockByHash", "params": ["0x…", false] }
→ {
    "number": "0x…",
    "hash": "0x…",
    "parentHash": "0x…",
    "nonce": "0x0000000000000000",
    "sha3Uncles": "0x1dcc4de8…",
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
    "transactions": ["0x…" | {tx object}],
    "uncles": [],
    "baseFeePerGas": "0x…"
  }
→ null si inconnu

Le 2ᵉ paramètre (fullTx) sélectionne le format des transactions
(hashs ou objets). transactions ne contient que les txs EVM ;
transactionIndex reste l'index dans le bloc complet.
Erreurs JSON-RPC
Code	Signification
-32600	Requête invalide (version, format)
-32601	Méthode inconnue
-32602	Paramètres invalides
-32603	Erreur interne
-32001	Entité absente
-32010	Transaction rejetée par le mempool
Limites V1

    eth_getBlockByNumber / eth_getBlockByHash : miner = adresse nulle
    (le proposeur Sango est une NativeAddress distincte d'une EvmAddress).

    stateRoot, transactionsRoot, receiptsRoot sont MPT
    Ethereum-compatibles structurellement, mais les valeurs encodées
    sont Sango (non RLP Ethereum). Un client Ethereum qui tente de les
    vérifier échouera — c'est un choix délibéré pour V1.

    eth_getProof : seul le tip est disponible (pas de snapshots
    historiques).

    Les txs EVM ne sont pas indexées par sender (eth_getLogs et
    eth_getTransactionByHash couvrent le besoin actuel).

Voir aussi

    Wallet — appelle ces méthodes pour toi

    Faucet — endpoint séparé, sur un autre port

    Devnet — config du réseau