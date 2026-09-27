Devnet — config Genesis, multi-nœuds, seeds

Un devnet est un réseau Sango jetable : chain ID dédié, comptes
pré-financés, un bloc toutes les 500 ms. Parfait pour développer,
tester, ou faire une démo.
Lancer un devnet
bash

rm -rf /tmp/sango-devnet
cargo run -p sango-node -- \
    --config examples/devnet.json \
    --data-dir /tmp/sango-devnet \
    --rpc-addr 127.0.0.1:8545 \
    --no-p2p

Flag	Rôle
--config PATH	Fichier Genesis JSON
--data-dir PATH	Répertoire de données RocksDB
--rpc-addr ADDR	Adresse du serveur RPC
--no-p2p	Désactive le réseau P2P (devnet mono-nœud)
Structure du Genesis — examples/devnet.json

Exemple réel :
json

{
  "_comment": "Devnet à un seul validateur. Les seeds sont PUBLIQUES — usage démo uniquement.",
  "chain_id_hex": "1111111111111111111111111111111111111111111111111111111111111111",
  "initial_supply_sango": "2000000000",
  "rewards_enabled": true,
  "self_validator_seed_hex": "01010101…",
  "validators": [
    {
      "seed_hex": "01010101…",
      "voting_power_sango": "100000",
      "commission_bps": 700
    }
  ],
  "allocations": [
    { "address_hex": "11111111…", "amount_sango": "500000000" },
    { "address_hex": "02291e07…", "amount_sango": "500000000",
      "public_key_hex": "c6822637…" },
    { "address_hex": "0x119a2d28…", "amount_sango": "1000000000" }
  ]
}

Champ	Rôle
chain_id_hex	32 bytes hex — identifiant unique de la chaîne
initial_supply_sango	Supply totale, en SANGO décimal
rewards_enabled	Active le calcul des récompenses de staking
self_validator_seed_hex	Seed du validateur « auto » (celle du nœud)
validators[]	Validateurs initiaux
validators[].seed_hex	Seed Ed25519 du validateur
validators[].voting_power_sango	Self-stake initial, en SANGO
validators[].commission_bps	Commission (basis points, 700 = 7 %)
allocations[]	Comptes pré-financés
allocations[].address_hex	Adresse native (avec ou sans 0x)
allocations[].amount_sango	Montant en SANGO décimal
allocations[].public_key_hex	Optionnel — clé publique si connue
Comptes « fantômes »

Une allocation sans public_key_hex crée un compte « fantôme » :
l'adresse a un solde, mais aucune clé publique n'est enregistrée. Le
protocole accepte une seule tx bootstrap de ce compte, qui déclare
la clé publique (le wallet le fait automatiquement à la première tx).
Multi-nœuds

Pour simuler plusieurs validateurs :

    lance N nœuds avec des --data-dir distincts ;

    donne à chaque nœud une --p2p-addr différente ;

    connecte-les avec --seeds :

bash

cargo run -p sango-node -- \
    --config examples/devnet.json \
    --data-dir /tmp/sango-node-2 \
    --rpc-addr 127.0.0.1:8546 \
    --p2p-addr 127.0.0.1:9002 \
    --seeds 127.0.0.1:9001

Seeds publiques

En devnet, les seeds sont jetables et publiques : 01010101…
et 11111111… sont dans examples/ et ne protègent rien. Ne les
utilise pas ailleurs qu'en local.
Wipe et relance

Pour repartir de zéro :
bash

rm -rf /tmp/sango-devnet

Le Genesis est réappliqué au prochain lancement. Fonds, état et
historique sont perdus — c'est voulu.
Voir aussi

    Quickstart

    Faucet — crédite les comptes devnet

    Architecture — comment un nœud traite un bloc