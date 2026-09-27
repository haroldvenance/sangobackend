
Faucet — distribution de SANGO en devnet/testnet

Le faucet est un service HTTP autonome qui envoie des SANGO depuis un
compte dédié vers une adresse demandée. Il est destiné au devnet et
au testnet — jamais au mainnet.
Lancer le faucet
bash

sango-faucet --config examples/faucet-devnet.json

Config par défaut :
json

{
  "rpc_url": "http://127.0.0.1:8545",
  "listen_addr": "127.0.0.1:3000",
  "faucet_seed_hex": "1111…1111",
  "amount_sango": "100",
  "cooldown_secs": 3600,
  "max_requests_per_ip": 5,
  "max_fee_base_units": 1000
}

Champs :
Champ	Requis	Défaut	Description
rpc_url	oui	—	URL du nœud RPC
listen_addr	oui	—	Adresse d'écoute HTTP
faucet_seed_hex	oui	—	Seed Ed25519 (32 bytes hex)
amount_sango	non	"100"	Montant par drip
cooldown_secs	non	3600	Cooldown par adresse et par IP
max_requests_per_ip	non	5	Drips max par IP sur le cooldown
max_fee_base_units	non	1000	max_fee des txs faucet

Important : le compte dérivé de faucet_seed_hex doit avoir du solde
dans le Genesis. Ajoute une ligne dans allocations[] de ton fichier
Genesis en conséquence.
Endpoints
POST /faucet — demander un drip

Requête :
bash

curl -X POST http://127.0.0.1:3000/faucet \
    -H 'Content-Type: application/json' \
    -d '{"address":"tsango1qg53upurn4c45nrchpv9gjdhudn65qdtv3xlde"}'

Réponse OK (200) :
json

{
  "tx_hash": "0x<64 hex>",
  "amount_base_units": "1000000000",
  "to": "0x<40 hex>"
}

Erreurs :
Code	Cas	Corps
400	JSON invalide	{ "error": "invalid json: …" }
400	Champ address manquant	{ "error": "missing field \address`" }`
400	Adresse mal formée	{ "error": "invalid address: …" }
429	Cooldown par adresse	{ "error": "rate limited", "reason": "address cooldown", "remaining_secs": N }
429	Limite par IP	{ "error": "rate limited", "reason": "ip limit" }
502	Erreur RPC (nœud injoignable)	{ "error": "rpc: …" }

Le tx_hash est le hash de la tx signée envoyée. Elle est incluse
dans un bloc en quelques centaines de ms (devnet).
GET /health — statut
bash

curl http://127.0.0.1:3000/health

json

{
  "status": "ok",
  "faucet_address": "0x<40 hex>",
  "balance_base_units": "999900000000"
}

Utile pour un monitoring externe (Prometheus, healthcheck Docker…).
GET / — mini-doc JSON
json

{
  "service": "sango-faucet",
  "version": 1,
  "endpoints": {
    "POST /faucet": { "body": { "address": "0x…" }, "returns": "tx_hash" },
    "GET /health": "returns status + faucet balance"
  },
  "amount_base_units": "1000000000",
  "cooldown_secs": 3600
}

Rate limiting

Deux niveaux indépendants :

    Par adresse : un même to ne peut redemander qu'après
    cooldown_secs. Retourne 429 avec remaining_secs.

    Par IP : une même IP source ne peut faire plus de
    max_requests_per_ip drips sur cooldown_secs. Retourne 429
    reason: "ip limit".

Exemple : cooldown_secs=3600, max_requests_per_ip=5 signifie
« 5 drips par heure et par IP, 1 drip par heure et par adresse ».

Ces deux limites sont calculées en mémoire (pas persistées). Un
redémarrage du faucet efface l'état.
Sécurité

    Le faucet signe avec une clé Ed25519 stockée en clair dans la config.
    Ne commit jamais une config avec un seed réel. Pour testnet public,
    préfère un fichier de config séparé non versionné, ou injecte le seed
    via variable d'environnement.

    En devnet/testnet uniquement. Ne jamais exposer un faucet en mainnet.

    Le montant par défaut (100 SANGO) est calibré pour des tests : ne pas
    augmenter sans raison.

Exemple complet

Terminal 1 — nœud devnet :
bash

rm -rf /tmp/sango-devnet
sango-node --config examples/devnet.json \
    --data-dir /tmp/sango-devnet --rpc-addr 127.0.0.1:8545 --no-p2p

Terminal 2 — faucet :
bash

sango-faucet --config examples/faucet-devnet.json

Terminal 3 — drip :
bash

ADDR=tsango1qg53upurn4c45nrchpv9gjdhudn65qdtv3xlde

# Health check
curl -s http://127.0.0.1:3000/health | jq

# Drip
curl -s -X POST http://127.0.0.1:3000/faucet \
    -H 'Content-Type: application/json' \
    -d "{\"address\":\"$ADDR\"}" | jq

# Second drip immédiat → 429
curl -s -X POST http://127.0.0.1:3000/faucet \
    -H 'Content-Type: application/json' \
    -d "{\"address\":\"$ADDR\"}" | jq

Intégration frontend

Un bouton « Get testnet SANGO » typique :

    Récupère l'adresse native de l'utilisateur (sango1… / tsango1…).

    POST /faucet { address }.

    Affiche un toast « Envoyé, hash 0x… ».

    Poll sango_getTransactionByHash jusqu'à ce que blockHeight soit
    non-null (inclusion en ~500 ms sur devnet).

Le faucet ne connaît pas les adresses EVM (0x…). Si ton UI
fonctionne en EVM, convertis d'abord côté client, ou ajoute un champ
evm_address séparé au faucet (non supporté en V1).