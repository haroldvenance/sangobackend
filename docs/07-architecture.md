Architecture — vue d'ensemble des crates

Sango est organisé en crates Rust, chacun avec une responsabilité
claire. Cette page donne la carte du dépôt.
Workspace

    ⚠️ Vérifier avec ls crates/ — certains crates peuvent exister
    sous d'autres noms, ou être ajoutés plus tard.

Crate	Rôle
sango-node	Binaire principal : assemble consensus, storage, RPC, P2P
sango-rpc	Serveur JSON-RPC (dispatch, HTTP, trait Backend)
sango-state	État (comptes, soldes, nonces, storage natif)
sango-faucet	Service HTTP de distribution de SANGO de test
sango-wallet	CLI client (signature, keyfile, appels RPC)
Flux d'une transaction native

    Wallet signe une tx Ed25519 avec la clé native.

    Wallet encode la tx au format canonique Sango et l'envoie via
    sango_sendTransaction.

    sango-rpc désérialise, valide, et passe au mempool.

    sango-node (proposeur) sélectionne la tx, l'exécute contre
    sango-state, produit un bloc.

    Le bloc est commité (RocksDB flush) et diffusé aux pairs P2P.

    L'index secondaire (tx_index) met à jour le mapping
    hash → (height, txIndex).

Flux d'une transaction EVM

    Wallet signe une tx secp256k1 (legacy / EIP-2930 / 1559 / 7702).

    Envoi via eth_sendRawTransaction.

    sango-rpc récupère le sender depuis la signature, valide nonce
    et balance, pousse au mempool.

    Exécution dans l'EVM embarquée contre l'état Sango.

    Logs (eth_getLogs) indexés par bloc, avec logIndex global.

RPC

Le serveur RPC expose deux namespaces :

    sango_* : API native (comptes, validateurs, délégations, staking) ;

    eth_* : API Ethereum-compatible (EVM, txs typées, receipts, logs).

Le trait Backend (dans sango-rpc/src/backend.rs) est l'interface
entre le serveur RPC et le nœud. sango-node/src/rpc_backend.rs en
fournit l'implémentation.
Stockage

    RocksDB comme moteur clé-valeur.

    Colonnes : blocs, état, index txs, validateurs, etc.

    Flush après chaque bloc — pas de perte sur Ctrl+C.

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

TLS

Le serveur RPC et le wallet supportent HTTPS optionnel :

    Côté serveur : --tls-cert / --tls-key (à confirmer).

    Côté wallet : --rpc-tls-ca (CA DER custom) ou --rpc-tls-insecure
    (devnet uniquement).

Voir aussi

    RPC — les méthodes exposées

    Devnet — configuration réseau

    Troubleshooting — erreurs fréquentes