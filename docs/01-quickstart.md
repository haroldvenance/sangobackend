Quickstart — devnet + RPC + wallet en 5 minutes

Objectif : lancer un nœud devnet, vérifier que le RPC répond, générer un
wallet, recevoir du SANGO depuis le faucet, et envoyer un transfert.
Prérequis

    Rust ≥ 1.75 (rustup show doit passer).

    curl et python3 (pour formater le JSON).

    Aucun port 8545 (RPC) ni 3001 (faucet) occupé.

Compile une fois (facultatif mais accélère la suite) :
bash

cargo build --workspace

Étape 1 — Lancer un nœud devnet

Terminal 1 :
bash

rm -rf /tmp/sango-devnet
cargo run -p sango-node -- \
    --config examples/devnet.json \
    --data-dir /tmp/sango-devnet \
    --rpc-addr 127.0.0.1:8545 \
    --no-p2p

Sortie attendue :
text

✓ Genesis appliqué : 3 comptes, 1 validateurs
✓ RPC listening on 127.0.0.1:8545
...
✓ Bloc #0 commit 0x…
✓ Bloc #1 commit 0x…

Le nœud commit un bloc toutes les 500 ms. Laisse-le tourner.
Étape 2 — Vérifier le RPC

Terminal 2 :
bash

# Chain ID natif
curl -s -X POST http://127.0.0.1:8545/rpc \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"sango_chainId","params":[],"id":1}'

# Hauteur courante
curl -s -X POST http://127.0.0.1:8545/rpc \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"sango_blockNumber","params":[],"id":1}'

# Informations chaîne
curl -s -X POST http://127.0.0.1:8545/rpc \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"sango_chainInfo","params":[],"id":1}' \
    | python3 -m json.tool

Étape 3 — Créer un wallet
bash

export SANGO_RPC=127.0.0.1:8545
export SANGO_KEYFILE=/tmp/alice.json

# Génère un keyfile v1 (clair)
cargo run -p sango-wallet -- \
    --keyfile $SANGO_KEYFILE \
    new

# Chiffre-le (recommandé) — passphrase demandée interactivement
cargo run -p sango-wallet -- \
    --keyfile $SANGO_KEYFILE \
    keyfile-encrypt

Note ton adresse affichée (0x…), tu vas en avoir besoin.
Étape 4 — Recevoir du SANGO depuis le faucet

Terminal 3 :
bash

cargo run -p sango-faucet -- --config examples/faucet-devnet.json

Puis :
bash

ADDR=<ton adresse native>

curl -s -X POST http://127.0.0.1:3001/faucet \
    -H 'Content-Type: application/json' \
    -d "{\"address\":\"$ADDR\"}" \
    | python3 -m json.tool

Attendu :
json

{
  "tx_hash": "0x…",
  "amount_base_units": "1000000000",
  "to": "0x…"
}

100 SANGO sont envoyés. Le compte est crédité au bloc suivant
(~500 ms).

Vérifie :
bash

cargo run -p sango-wallet -- \
    --keyfile $SANGO_KEYFILE \
    --rpc $SANGO_RPC \
    balance

Étape 5 — Envoyer un transfert
bash

# Adresse de Bob (fictive ici — utilise la sienne en vrai)
BOB=0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

cargo run -p sango-wallet -- \
    --keyfile $SANGO_KEYFILE \
    --rpc $SANGO_RPC \
    send --to $BOB --amount 1.5

Attendu :
text

✓ Transaction envoyée
  Hash : 0x…

Vérifie dans les logs du node (terminal 1) : un nouveau bloc contient
la tx, et le solde de Bob augmente.
bash

cargo run -p sango-wallet -- \
    --rpc $SANGO_RPC \
    balance $BOB
# → 15000000 base units (1.5 SANGO)

Étape 6 — EVM (facultatif)

Attache une clé EVM au même keyfile :
bash

cargo run -p sango-wallet -- \
    --keyfile $SANGO_KEYFILE \
    evm-new

Récupère ton adresse EVM :
bash

cargo run -p sango-wallet -- \
    --keyfile $SANGO_KEYFILE \
    evm-address

C'est un compte distinct du compte natif, même s'il est dans le
même keyfile. Il n'a pas encore de solde EVM.
Arrêter proprement

Terminal 1 : Ctrl+C (les écritures RocksDB sont flushées après chaque
bloc, pas de perte).

Pour tout recommencer à zéro : rm -rf /tmp/sango-devnet.
Suite

    Wallet CLI — toutes les commandes natives + EVM

    RPC — référence complète des méthodes

    Faucet — config, rate limit

    Devnet — config Genesis, seeds