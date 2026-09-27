
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

    ⚠️ Vérifier les champs exacts dans examples/faucet-devnet.json.

Champs principaux :
Champ	Rôle
listen_addr	Adresse d'écoute HTTP (défaut 127.0.0.1:3001)
rpc_url	Endpoint RPC du nœud Sango
keyfile	Keyfile du compte faucet
amount_base_units	Montant distribué (défaut 1000000000 = 100 SANGO)
rate_limit	Quotas par adresse / par IP
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

Le faucet applique un double quota :

    par adresse : N requêtes / heure ;

    par IP : M requêtes / heure.

Au-delà, le faucet retourne HTTP 429 avec un JSON d'erreur.
Erreurs courantes
Symptôme	Cause	Fix
connection refused	Nœud RPC non lancé	Démarre le node d'abord
HTTP 429	Quota dépassé	Attends, ou change d'adresse
HTTP 400	Adresse mal formée	Vérifie 0x + 40 hex
HTTP 500	Compte faucet vide	Réapprovisionne via Genesis
Voir aussi

    Quickstart — mise en route complète

    RPC — méthodes exposées par le nœud

    Devnet — config Genesis du compte faucet
    