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

    ⚠️ Vérifier les champs exacts dans examples/devnet.json.

Champs attendus :
Champ	Rôle
chain_id	32 bytes hex, identifiant unique de la chaîne
accounts	Liste d'adresses pré-financées
validators	Validateurs initiaux (adresse + stake)
params	Paramètres consensus (block time, etc.)
genesis_time	Timestamp de démarrage

Le chain_id est crucial : il signe chaque transaction et empêche
le replay entre réseaux. Change-le pour isoler un réseau de test.
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

En devnet, les seeds sont jetables. Ne les utilise pas pour autre
chose qu'un test local. Le réseau peut être wipé à tout moment.
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