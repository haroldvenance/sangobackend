# Sango — Documentation utilisateur

Bienvenue. Cette documentation s'adresse à toute personne qui veut
**lancer un nœud**, **utiliser le wallet**, ou **parler au RPC** de Sango
en devnet ou testnet.

## Parcours conseillé

| Étape | Document | Durée |
|---|---|---|
| 1 | [Quickstart](./01-quickstart.md) — lancer un devnet + RPC + wallet en 5 min | 5 min |
| 2 | [Wallet CLI](./02-wallet.md) — toutes les commandes natives et EVM | 20 min |
| 3 | [RPC](./03-rpc.md) — méthodes `sango_*` et `eth_*` | référence |
| 4 | [Faucet](./04-faucet.md) — distribuer du SANGO de test | 10 min |
| 5 | [Devnet](./05-devnet.md) — config Genesis, multi-nœuds, seeds | 15 min |
| 6 | [Troubleshooting](./06-troubleshooting.md) — erreurs fréquentes | référence |
| 7 | [Architecture](./07-architecture.md) — vue d'ensemble des crates | référence |

## Démarrage ultra-rapide

Si tu veux juste voir quelque chose marcher :

```bash
# Terminal 1 — un nœud devnet
cargo run -p sango-node -- \
    --config examples/devnet.json \
    --data-dir /tmp/sango-devnet \
    --rpc-addr 127.0.0.1:8545 \
    --no-p2p

# Terminal 2 — un faucet (facultatif)
cargo run -p sango-faucet -- --config examples/faucet-devnet.json

# Terminal 3 — une requête RPC
curl -s -X POST http://127.0.0.1:8545/rpc \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"sango_chainInfo","params":[],"id":1}' \
    | python3 -m json.tool

Plus de détails : Quickstart.
Ce que Sango n'est pas (encore)

    ❌ Pas de mainnet public déployé.

    ❌ Pas de testnet public déployé (prévu en P3.5).

    ⚠️ Devnet uniquement pour l'instant : seeds publiques, données
    jetables, à wiper régulièrement.

Le RPC et le wallet sont API-stables pour un usage devnet. Un
changement de protocole (hard fork) sera annoncé par bump de
chain_id dans le Genesis.
Signaler un problème

    Bug RPC / wallet : ouvre une issue avec la sortie exacte de la commande.

    Comportement inattendu : inclus le chain_id (sango_chainId) et la
    hauteur (sango_blockNumber).