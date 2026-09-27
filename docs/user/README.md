
# Sango — Documentation utilisateur

Bienvenue. Cette documentation couvre l'usage de la blockchain **Sango V1**
en devnet et testnet. Elle s'adresse aux développeurs qui veulent lancer
un nœud, utiliser le wallet, appeler le RPC ou intégrer un frontend.

> **Note** : ceci est la documentation **utilisateur**. La spécification
> normative du protocole vit dans `SANGO PROTOCOL FREEZE V1`.

## Je veux…

| Objectif | Fichier |
|---|---|
| Lancer un nœud devnet et envoyer ma première transaction | [`onboarding.md`](onboarding.md) |
| Créer un wallet, signer une tx native ou EVM | [`wallet.md`](wallet.md) |
| Appeler le RPC depuis un client (curl, TS, Go, Rust) | [`rpc.md`](rpc.md) |
| Naviguer l'explorer web | [`explorer.md`](explorer.md) |
| Obtenir des SANGO de test | [`faucet.md`](faucet.md) |

## Vue d'ensemble

Sango est une blockchain Rust organisée en workspace multi-crates. Pour
l'utilisateur, quatre binaires suffisent :

| Binaire | Rôle |
|---|---|
| `sango-node` | Nœud full : consensus, stockage, RPC JSON-RPC |
| `sango-wallet` | CLI : clés, signature, envoi de transactions |
| `sango-faucet` | Service HTTP qui distribue des SANGO sur devnet/testnet |
| `sango-explorer` | Explorer web minimaliste (blocs, txs, adresses) |

## Deux familles de transactions

Sango V1 supporte **deux formats de transactions** coexistant dans un même
bloc :

- **Natives Sango** : signature Ed25519, `TxKind` dédié (transfer, bond,
  delegate, …). Adresses `sango1…` / `tsango1…` (bech32m).
- **EVM** : typed-transactions Ethereum (Legacy, EIP-2930, EIP-1559,
  EIP-7702), signature secp256k1. Adresses `0x…` (hex).

Les deux sont exposées via des namespaces RPC séparés : `sango_*` et
`eth_*`.

## Points de repère

- **Base units** : 1 SANGO = 10 000 000 base units (7 décimales).
  Tous les montants RPC sont en base units, en string décimale.
- **Chain ID natif** : 32 bytes, défini dans le Genesis (par réseau).
- **Chain ID EVM** : `u64`, défaut `0x53414e474f` (« SANGO » en ASCII).
- **Bloc time devnet** : 500 ms.

## Support

Pour les bugs et questions : ouvre un ticket sur le repo. Pour les
questions de consensus (Freeze), réfère-toi à la spécification.
EOF

# =============================================================================
# docs/user/onboarding.md
# =============================================================================
cat > docs/user/onboarding.md <<'EOF'
# Onboarding — premier nœud, premier wallet, première tx

Objectif : en 15 minutes, tu auras un nœud devnet qui produit des blocs, un
wallet, et tu auras envoyé une transaction.

## 1. Prérequis

- **Rust** ≥ 1.75 (stable) : `rustup install stable`
- **Linux / macOS** recommandé. Windows via WSL2.
- **~2 Go d'espace disque** pour le workspace + le `data-dir` devnet.

Clone le repo et compile :

```bash
git clone https://github.com/sango/sango
cd sango
cargo build --release

Les binaires sont dans target/release/ :
sango-node, sango-wallet, sango-faucet, sango-explorer.
2. Lancer un nœud devnet (mode autonome)

Le plus simple : un seul nœud validateur, self-loopback, sans P2P.

Config Genesis (examples/devnet.json) : un fichier JSON qui définit
le chain_id, la supply initiale, les validateurs, les allocations. Le
fichier par défaut du repo suffit pour un premier essai.

Lancer le nœud :
bash

rm -rf /tmp/sango-devnet
./target/release/sango-node \
    --config examples/devnet.json \
    --data-dir /tmp/sango-devnet \
    --rpc-addr 127.0.0.1:8545 \
    --no-p2p

Sortie attendue :
text

✓ Genesis appliqué : N comptes, M validateurs
✓ RPC TLS désactivé (HTTP clair)
✓ Faucet addr  : 0x...
✓ Bloc #1 commit 0x...
✓ Bloc #2 commit 0x...

Le nœud produit un bloc toutes les 500 ms (configurable dans le code).
3. Vérifier que le RPC répond
bash

curl -s -X POST http://127.0.0.1:8545/rpc \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"sango_chainInfo","params":[],"id":1}' | jq

Résultat :
json

{
  "jsonrpc": "2.0",
  "result": {
    "chainId": "0x1111…",
    "height": 42,
    "validatorCount": 1,
    "protocolVersion": 1
  },
  "id": 1
}

4. Créer un wallet

sango-wallet gère deux clés dans le même keyfile :

    une clé Ed25519 pour les txs natives (adresse bech32m) ;

    une clé secp256k1 pour les txs EVM (adresse 0x…).

bash

./target/release/sango-wallet \
    --keyfile /tmp/my-wallet.json \
    new

La commande demande un passphrase (Argon2id + ChaCha20-Poly1305). Note-le :
il n'y a aucun moyen de le récupérer.

Afficher les adresses :
bash

./target/release/sango-wallet --keyfile /tmp/my-wallet.json address
# → Native : tsango1qg53upurn4c45nrchpv9gjdhudn65qdtv3xlde
# → EVM    : 0xabcd…1234

5. Obtenir des SANGO du faucet

Lance le faucet dans un second terminal :
bash

./target/release/sango-faucet --config examples/faucet-devnet.json

Puis demande un drip :
bash

ADDR=tsango1qg53upurn4c45nrchpv9gjdhudn65qdtv3xlde

curl -s -X POST http://127.0.0.1:3000/faucet \
    -H 'Content-Type: application/json' \
    -d "{\"address\":\"$ADDR\"}" | jq

Réponse :
json

{
  "tx_hash": "0x…",
  "amount_base_units": "1000000000",
  "to": "0x…"
}

Le montant par défaut est 100 SANGO (configurable dans la config
faucet). Attends un ou deux blocs (≈ 1 s) avant que le solde n'apparaisse.
6. Vérifier le solde
bash

./target/release/sango-wallet --keyfile /tmp/my-wallet.json balance
# → 100 SANGO

Ou via RPC :
bash

curl -s -X POST http://127.0.0.1:8545/rpc \
    -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"sango_getBalance\",\"params\":[\"$ADDR\"],\"id\":1}" | jq
# → "result": "1000000000"

7. Envoyer ta première transaction

Envoie 1 SANGO vers une autre adresse :
bash

./target/release/sango-wallet --keyfile /tmp/my-wallet.json \
    send --to tsango1... --amount 1

La CLI signe, appelle sango_sendTransaction, et affiche le hash de tx.
Le nœud l'inclut dans le prochain bloc (≈ 500 ms).

Suivre l'inclusion :
bash

curl -s -X POST http://127.0.0.1:8545/rpc \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"sango_getTransactionByHash","params":["0x<hash>"],"id":1}' | jq

Une fois incluse, la réponse contient blockHeight, blockHash, txIndex.
8. Explorer web

Lance l'explorer :
bash

./target/release/sango-explorer --config examples/explorer-devnet.json

Puis ouvre http://127.0.0.1:8090/ dans un navigateur. Tu verras les
derniers blocs, et tu pourras cliquer sur ta tx.
Étape suivante

    Pour aller plus loin côté wallet (staking, EVM, keystore) →
    wallet.md

    Pour toutes les méthodes RPC → rpc.md

    Pour l'explorer → explorer.md

    Pour le faucet → faucet.md

Dépannage

error: Address already in use

Un autre service occupe le port. Vérifie :
bash

ss -tlnp | grep 8545      # RPC
ss -tlnp | grep 8090      # Explorer
ss -tlnp | grep 3000      # Faucet

Change le port dans la config ou avec --rpc-addr.

Le nœud démarre mais ne produit pas de blocs

Vérifie que tu es bien un validateur : le log au démarrage doit afficher
Validator : 0x…. Sinon, ton self_validator_seed_hex ne correspond à
aucun validateur dans le Genesis.

data-dir corrompu après un changement de schéma

En devnet, c'est normal : rm -rf /tmp/sango-devnet et relance. Les
migrations de storage ne sont pas automatiques en V1.