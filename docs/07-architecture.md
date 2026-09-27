Architecture — vue d'ensemble des crates

Sango est organisé en crates Rust, chacun avec une responsabilité
claire. Cette page donne la carte du dépôt.
Workspace
Crate	Rôle
sango-types	Types de base : adresses, hashes, montants
sango-primitives	Primitives consensus partagées
sango-crypto	Ed25519, secp256k1, KDF, AEAD
sango-codec	Encodage canonique Sango (tx, blocs)
sango-tx	Structures de transactions natives et EVM
sango-state	État (comptes, soldes, nonces, storage natif)
sango-storage	Persistance RocksDB (colonnes, index)
sango-mpt	Merkle Patricia Trie (état, racines)
sango-mempool	Pool de transactions en attente
sango-exec	Exécution des txs contre l'état
sango-evm	EVM embarquée (txs typées, receipts, logs)
sango-staking	Bond/unbond, délégations, validateurs, jail
sango-consensus	Proposeur, commit, timers
sango-p2p	Réseau pair-à-pair, seeds, gossip
sango-rpc	Serveur JSON-RPC (dispatch, HTTP, trait Backend)
sango-node	Binaire principal — assemble tout
sango-wallet	CLI client (signature, keyfile, appels RPC)
sango-faucet	Service HTTP de distribution de SANGO de test
Flux d'une transaction native

    Wallet signe une tx Ed25519 avec la clé native.

    Wallet encode la tx au format canonique Sango (sango-codec)
    et l'envoie via sango_sendTransaction.

    sango-rpc désérialise, valide, et pousse au sango-mempool.

    sango-node (proposeur) sélectionne la tx, l'exécute via
    sango-exec contre sango-state, produit un bloc.

    Le bloc est commité dans sango-storage (flush RocksDB) et
    diffusé via sango-p2p.

    L'index secondaire met à jour le mapping
    hash → (height, txIndex).

Flux d'une transaction EVM

    Wallet signe une tx secp256k1 (legacy / EIP-2930 / 1559 / 7702).

    Envoi via eth_sendRawTransaction.

    sango-rpc récupère le sender depuis la signature, valide nonce
    et balance, pousse au sango-mempool.

    Exécution dans sango-evm contre l'état Sango.

    Logs (eth_getLogs) indexés par bloc, avec logIndex global.

RPC

Le serveur RPC expose deux namespaces :

    sango_* : API native (comptes, validateurs, délégations, staking) ;

    eth_* : API Ethereum-compatible (EVM, txs typées, receipts, logs).

Le trait Backend (dans sango-rpc/src/backend.rs) est l'interface
entre le serveur RPC et le nœud. sango-node/src/rpc_backend.rs en
fournit l'implémentation.
Stockage

    RocksDB comme moteur clé-valeur (sango-storage).

    Colonnes : blocs, état, index txs, validateurs, etc.

    Flush après chaque bloc — pas de perte sur Ctrl+C.

    sango-mpt fournit les racines Merkle (état, tx, receipts).

L'index secondaire des transactions (sango-node/src/tx_index.rs)
permet sango_getTransactionsByAddress avec pagination.
Consensus

    Proposeur unique en V1 (devnet), un bloc toutes les 500 ms.

    Signature Ed25519 des blocs.

    chain_id dans le Genesis, signé par chaque tx native.

P2P

    Désactivable avec --no-p2p (devnet mono-nœud).

    --seeds pour rejoindre un réseau existant.

    --p2p-addr pour fixer l'adresse d'écoute.

Staking

sango-staking gère :

    le cycle de vie d'un validateur (register, unjail, commission) ;

    les délégations (delegate / undelegate / claim) ;

    les unbondings avec maturation différée.

TLS

Le serveur RPC et le wallet supportent HTTPS optionnel :

    Côté serveur : --tls-cert / --tls-key.

    Côté wallet : --rpc-tls-ca (CA DER custom) ou --rpc-tls-insecure
    (devnet uniquement).

Voir aussi

    RPC — les méthodes exposées

    Devnet — configuration réseau

    Troubleshooting — erreurs fréquentes