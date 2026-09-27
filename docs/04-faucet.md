
# Faucet — distribuer du SANGO de test

Le faucet est un service HTTP qui crédite une adresse native avec des
SANGO de test. Il n'est **pas** destiné à la production : il n'existe
que pour alimenter les comptes devnet/testnet.

## Lancement

```bash
cargo run -p sango-faucet -- --config examples/faucet-devnet.json

Sortie attendue :
text

✓ Faucet listening on 127.0.0.1:3001
✓ RPC connecté sur 127.0.0.1:8545

Le faucet a besoin d'un nœud RPC joignable (celui du devnet). Lance le
nœud avant le faucet.
Config — examples/faucet-devnet.json

Exemple réel :
json

{
  "rpc_url": "http://127.0.0.1:8545",
  "listen_addr": "127.0.0.1:3001",
  "faucet_seed_hex": "1111111111111111111111111111111111111111111111111111111111111111",
  "amount_sango": "100",
  "cooldown_secs": 3600,
  "max_requests_per_ip": 5,
  "max_fee_base_units": 1000
}

Champ	Rôle
rpc_url	Endpoint RPC du nœud Sango
listen_addr	Adresse d'écoute HTTP (défaut 127.0.0.1:3001)
faucet_seed_hex	Seed Ed25519 du compte faucet (32 bytes hex)
amount_sango	Montant distribué, en SANGO décimal (ex. "100")
cooldown_secs	Délai minimum entre deux requêtes par adresse
max_requests_per_ip	Quota par IP (fenêtre glissante)
max_fee_base_units	max_fee appliqué à la tx faucet

⚠️ Ne mets jamais la vraie seed du faucet d'un réseau public ici.
faucet_seed_hex est un secret — quiconque la lit peut vider le compte.
Endpoint HTTP
POST /faucet

Requête :
bash

curl -s -X POST http://127.0.0.1:3001/faucet \
    -H 'Content-Type: application/json' \
    -d '{"address":"0x<adresse_native>"}' \
    | python3 -m json.tool

Réponse :
json

{
  "tx_hash": "0x…",
  "amount_base_units": "1000000000",
  "to": "0x…"
}

Le compte est crédité au bloc suivant (~500 ms sur devnet).
Rate limiting

Deux garde-fous indépendants :

    par adresse : cooldown_secs (3600 s = 1 h par défaut) ;

    par IP : max_requests_per_ip (5 par défaut).

Au-delà, le faucet retourne HTTP 429.
Erreurs courantes
Symptôme	Cause	Fix
connection refused	Nœud RPC non lancé	Démarre le node d'abord
HTTP 429	Cooldown ou quota IP dépassé	Attends, ou change d'adresse
HTTP 400	Adresse mal formée	Vérifie 0x + 40 hex
HTTP 500	Compte faucet vide	Réapprovisionne via Genesis
Voir aussi

    Quickstart — mise en route complète

    RPC — méthodes exposées par le nœud

    Devnet — config Genesis du compte faucet