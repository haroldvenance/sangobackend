Wallet — CLI, keystore, txs natives et EVM

sango-wallet est la CLI de référence pour manipuler un keyfile Sango.
Elle gère deux clés dans un même keyfile :

    Ed25519 : signe les transactions natives (Transfer, Bond, Delegate…).
    Adresse associée : bech32m (sango1… / tsango1…).

    secp256k1 : signe les transactions EVM (Legacy, EIP-2930, EIP-1559,
    EIP-7702). Adresse associée : hex 0x….

Usage général
bash

sango-wallet [--keyfile <PATH>] [--rpc <URL>] <commande> [options]

Toutes les commandes acceptent --help.
Commandes principales
new — créer un keyfile
bash

sango-wallet --keyfile wallet.json new

Demande un passphrase (2× pour confirmation). Chiffre avec Argon2id +
ChaCha20-Poly1305. Le fichier est écrit avec les permissions 0600.
address — afficher les adresses
bash

sango-wallet --keyfile wallet.json address
# Native : tsango1qg53upurn4c45nrchpv9gjdhudn65qdtv3xlde
# EVM    : 0x2291e07839d715a4c78b8585449b7e367aa01ab

pubkey — afficher la clé publique Ed25519

Utile pour un bootstrap de compte (première tx d'un compte fantôme) :
bash

sango-wallet --keyfile wallet.json pubkey

balance — solde natif
bash

sango-wallet --keyfile wallet.json --rpc http://127.0.0.1:8545 balance
# → 100 SANGO

Le solde affiché est celui du compte natif. Pour le solde EVM, utilise
eth_getBalance via curl (ou une lib Ethereum).
send — transfert natif
bash

sango-wallet --keyfile wallet.json --rpc http://127.0.0.1:8545 \
    send --to tsango1... --amount 1.5

Le --amount accepte les décimales (jusqu'à 7). La CLI :

    récupère le nonce et la chain_id via sango_getAccount / sango_chainId ;

    construit une tx TxKind::Transfer ;

    signe avec la clé Ed25519 ;

    envoie via sango_sendTransaction ;

    affiche le hash.

Staking

Toutes les opérations de staking sont des TxKind natifs natifs, signés
Ed25519. La CLI expose une commande par opération.
stake — self-stake (Bond)

Transforme une partie du solde en self-stake validateur.
bash

sango-wallet ... stake --amount 100000

Minimum : 100 000 SANGO. Le self-stake ne peut jamais retomber en
dessous de ce minimum (sauf slash).
delegate — déléguer à un validateur
bash

sango-wallet ... delegate --validator tsango1... --amount 5000

La délégation produit des récompenses PoS. L'auto-délégation est interdite.
undelegate — retirer une délégation
bash

sango-wallet ... undelegate --validator tsango1... --amount 2000

Déclenche une période d'unbonding de 14 jours. Les fonds sont crédités
automatiquement après maturation (traité à chaque bloc).
unbond — retirer du self-stake
bash

sango-wallet ... unbond --amount 10000

Même délai de 14 jours, et doit laisser au moins 100 000 SANGO en
self-stake.
claim-rewards — réclamer les récompenses
bash

sango-wallet ... claim-rewards --validator tsango1...

Crédite les récompenses accumulées sur le solde natif.
register-validator — enregistrer un validateur
bash

sango-wallet ... register-validator --commission-bps 700

    --commission-bps : 0 à 1000 (0 % à 10 %). Défaut 700 (7 %).

    Nécessite un self-stake ≥ 100 000 SANGO.

update-commission — modifier la commission
bash

sango-wallet ... update-commission --commission-bps 900

Prend effet après un délai de 7 jours (activation automatique à chaque
bloc).
unjail — sortir du jail
bash

sango-wallet ... unjail

N'est possible qu'après expiration de la période de jail (double-sign
= 21 jours ; downtime = 5 000 blocs).
Transactions EVM

La CLI peut signer des typed-transactions Ethereum (Legacy, EIP-2930,
EIP-1559, EIP-7702). Elle génère le RLP signé, prêt à être envoyé via
eth_sendRawTransaction.

    Note : les commandes EVM exactes sont documentées par
    sango-wallet --help. Le point important est que la signature est
    conforme EIP-155 pour Legacy et supporte access_list pour les types
    typés.

Les signatures secp256k1 sont déterministes (RFC 6979), donc rejouables
byte-à-byte à partir du même message et de la même clé.
Keystore

Deux formats de keyfile existent :
Version	Crypto	Statut
V1	Argon2id + ChaCha20-Poly1305	historique (P1)
V2	idem V1 + métadonnées	courant

    Les deux formats coexistent et sont détectés au chargement.

    Un keyfile V2 refuse de charger comme V1 et inversement (protection
    contre les downgrades).

    Le fichier doit être en 0600, sinon la CLI refuse de charger.

Bootstrap de compte

Un compte qui reçoit un crédit avant d'avoir enregistré sa clé publique
est un compte fantôme : il ne peut pas émettre de transactions.

La première transaction d'un tel compte doit déclarer la clé publique
(champ public_key: Some(pk) dans la tx). La CLI le fait
automatiquement : elle détecte que la clé n'est pas on-chain, l'inclut
dans la tx, et le nœud l'enregistre lors de l'application.

Après ce bootstrap, les transactions suivantes sont normales.
Sécurité

    Ne partage jamais le keyfile ni le passphrase.

    Le fichier est chiffré, mais un attaquant avec le fichier + le
    passphrase peut tout signer.

    Pour un wallet chaud en production, préfère un HSM ou un signer distant.

    Les clés privées ne sont jamais envoyées au nœud : seule la
    transaction signée l'est.