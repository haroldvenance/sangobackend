
Explorer — navigation web

L'explorer Sango est un serveur HTML minimaliste (server-side
rendering, pas de JS). Il lit le RPC et affiche blocs, txs, adresses.
Lancer l'explorer
bash

sango-explorer --config examples/explorer-devnet.json

Config par défaut (voir examples/explorer-devnet.json) :
json

{
  "rpc_url": "http://127.0.0.1:8545",
  "listen_addr": "127.0.0.1:8090",
  "network_name": "Sango Devnet"
}

Ouvre http://127.0.0.1:8090/ dans un navigateur.
Routes
GET / — Dashboard

    Chain ID, hauteur actuelle, nombre de validateurs.

    Les 10 derniers blocs.

GET /blocks?limit=N&offset=M

Liste paginée des blocs, du plus récent au plus ancien.

Paramètres :

    limit : nombre de blocs par page. Défaut 20, max 100.

    offset : index de départ (0 = tip). Défaut 0.

    page : fallback compat. ?page=2 équivaut à
    ?limit=<20 par défaut>&offset=<(2−1)×limit>. Si page et
    offset sont fournis, page gagne.

Exemples :
text

/blocks                      → 20 premiers blocs
/blocks?limit=5              → 5 premiers blocs
/blocks?limit=5&offset=5     → blocs 5..10
/blocks?page=3               → blocs 40..60 (par défaut limit=20)

GET /block/:height

Détail d'un bloc :

    Toutes les métadonnées du header (hash, parent, timestamp, proposeur).

    Gas used / limit, base fee.

    Roots (transaction_root, state_root, receipt_root).

    Liste complète des transactions (natives + EVM), chacune cliquable.

    Section bonus : vue Ethereum parallèle (eth_getBlockByNumber)
    pour comparer les deux représentations.

GET /tx/:hash

Détail d'une transaction :

    Hash, bloc, index dans le bloc.

    Si native : type (TxKind), sender, recipient, nonce, valeur, gas,
    fees, éventuelle clé publique déclarée.

    Si EVM : type (0x00..0x04), sender (récupéré
    cryptographiquement), to/input/nonce/valeur/gas.

    Section receipt (EVM uniquement) : statut, gas used, logs avec
    adresse, topics et data.

GET /address/:addr?limit=N&offset=M

Détail d'une adresse :

    Solde natif, nonce, clé publique enregistrée (ou « fantôme »).

    Info validateur si l'adresse est un validateur (self-stake, commission,
    jailed).

    Délégations émises par l'adresse.

    Unbondings en attente (montant + timestamp de maturation).

    Transactions natives émises — paginées.

Adresses acceptées : 0x… (hex, 40 chars) ou sango1… /
tsango1… (bech32m).
text

/address/0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
/address/tsango1qg53upurn4c45nrchpv9gjdhudn65qdtv3xlde
/address/tsango1qg5…?limit=50&offset=100

Pagination : mêmes paramètres que /blocks.
GET /validators

Liste tous les validateurs avec self-stake, total délégué, voting power,
commission, statut jailed. Chaque adresse est cliquable.
GET /search?q=…

Routage intelligent. La query est interprétée dans cet ordre :
Forme	Interprétation	Exemple
Nombre pur	Hauteur de bloc	42, 0, 1000
0x… (40 hex)	Adresse native	0xaaaa…
0x… (64 hex)	Hash de tx ou de bloc	0x1234…
sango1… / tsango1…	Adresse native bech32m	tsango1qg5…
Autre	Erreur explicative	—

Pour un hash de 64 chars, l'explorer tente d'abord une tx, puis un bloc.
GET /health

Statut JSON de la chaîne (chainId, height, validatorCount, …). Utile pour
un monitoring externe.
Navigation entre pages

Les liens cliquables forment un graphe navigable :

    /block/:height → chaque tx de la liste → /tx/:hash

    /block/:height → parent → /block/:height-1

    /block/:height → proposeur → /address/:addr

    /tx/:hash → bloc → /block/:height

    /tx/:hash → sender / recipient → /address/:addr

    /address/:addr → chaque tx émise → /tx/:hash

    /address/:addr → chaque validateur délégué → /address/:val

Style

    Dark mode par défaut, CSS inline (~60 lignes).

    Aucun JavaScript : tout le rendu est server-side.

    Pas de framework, pas de dépendance frontend.

    Les adresses et hashs longs sont tronqués (0x1234…abcd) mais restent
    cliquables.

Limitations V1

    Pas de recherche full-text.

    Pas de graphiques (production de blocs, prix du gas…).

    Pas d'indexation par mot-clé de contrat.

    Pas de cache HTTP (chaque requête touche le RPC).

Dépannage

« RPC non joignable » au démarrage

L'explorer a besoin d'un nœud accessible. Vérifie que
rpc_url correspond à un nœud qui tourne :
bash

curl -s -X POST $RPC_URL/rpc -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"sango_blockNumber","params":[],"id":1}'

« Page vide » dans /blocks

Le tip a moins de blocs que l'offset demandé, ou le nœud vient juste de
démarrer. Vérifie sango_blockNumber.

Adresse bech32m refusée

Le HRP doit être sango (mainnet) ou tsango (testnet/devnet). Toute
autre chaîne est rejetée avec un message explicite.
