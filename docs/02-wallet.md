gWallet CLI — sango-wallet

CLI synchrone qui parle au RPC d'un nœud Sango. Gère deux types de clés
indépendants dans le même keyfile :

    une clé native Ed25519 (transferts SANGO, staking, délégations) ;

    une clé EVM secp256k1 (optionnelle, ajoutée par evm-new).

Aide rapide
bash

cargo run -p sango-wallet -- --help

Options globales

Elles se placent avant la commande :
Option	Défaut	Rôle
--rpc URL	127.0.0.1:8545	Endpoint RPC
--keyfile PATH	~/.sango/wallet.json	Chemin du keyfile
--rpc-tls-ca PATH	—	CA DER pour HTTPS custom
--rpc-tls-insecure	—	Accepte tout certificat (devnet)

Variables d'environnement :

    SANGO_WALLET_PASSPHRASE : passphrase pour les keyfiles v2. Si absente,
    le wallet demande interactivement.

Commandes natives
new — générer un keyfile
bash

sango-wallet --keyfile /tmp/alice.json new

Crée un keyfile v1 en clair (permissions 0600). Affiche l'adresse
native. Sauvegarde ce fichier — sans lui, les fonds sont perdus.
address, pubkey
bash

sango-wallet --keyfile /tmp/alice.json address
# → 0x<40 hex>

sango-wallet --keyfile /tmp/alice.json pubkey
# → 0x<64 hex>

balance [ADDR], nonce [ADDR]
bash

sango-wallet --rpc 127.0.0.1:8545 --keyfile /tmp/alice.json balance
sango-wallet --rpc 127.0.0.1:8545 balance 0xbbbb…

Sortie balance : <base units> base units (<SANGO> SANGO).
Sortie nonce : un entier.
info — infos chaîne
bash

sango-wallet --rpc 127.0.0.1:8545 info

Affiche le JSON de sango_chainInfo.
send — transfert natif
bash

sango-wallet --keyfile /tmp/alice.json send --to 0xbbbb… --amount 1.5

    --to : adresse native (20 bytes hex).

    --amount : décimal SANGO, jusqu'à 7 décimales (1.2345678 OK,
    1.12345678 rejeté).

Note bootstrap : à la première tx d'un compte fraîchement crédité
(« fantôme »), le wallet déclare automatiquement la clé publique dans la
transaction. Le protocole accepte ce bootstrap une seule fois.
Staking
bash

# Self-stake (min. 100 000 SANGO pour devenir validateur)
sango-wallet --keyfile /tmp/v.json stake --amount 100000

# Retrait (déclenche unbonding 14 j)
sango-wallet --keyfile /tmp/v.json unstake --amount 1000

Délégation
bash

# Déléguer à un validateur
sango-wallet --keyfile /tmp/alice.json \
    delegate --validator 0xvvvv… --amount 500

# Retirer (unbonding 14 j)
sango-wallet --keyfile /tmp/alice.json \
    undelegate --validator 0xvvvv… --amount 200

# Réclamer les récompenses accumulées
sango-wallet --keyfile /tmp/alice.json \
    claim --validator 0xvvvv…

Cycle de vie d'un validateur
bash

# S'enregistrer (commission en basis points, max 1000 = 10 %)
sango-wallet --keyfile /tmp/v.json \
    register-validator --commission-bps 700 --amount 100000

# Modifier la commission (prend effet après 7 j)
sango-wallet --keyfile /tmp/v.json \
    update-commission --new-bps 800

# Sortir du jail après une période de downtime
sango-wallet --keyfile /tmp/v.json unjail

Récapitulatif du gas

Le gas est fixe par type de tx (pas d'estimation) :
Type	Gas
Transfer	21 000
Bond / Unbond	50 000
Delegate / Undelegate	80 000
ClaimRewards	40 000
RegisterValidator	200 000
UpdateCommission	30 000
Unjail	30 000

max_fee par défaut du wallet : 1_000_000 base units/gas,
priority_fee : 0.
Commandes EVM
evm-new — attacher une clé EVM
bash

# Keyfile v1
sango-wallet --keyfile /tmp/alice.json evm-new

# Keyfile v2 (demande la passphrase)
sango-wallet --keyfile /tmp/alice.json evm-new

Ajoute un secret secp256k1 au keyfile et affiche l'adresse EVM
(0x<40 hex>). Idempotent (erreur si déjà présent).
evm-address, evm-balance [ADDR], evm-nonce [ADDR]
bash

sango-wallet --keyfile /tmp/alice.json evm-address
sango-wallet --rpc 127.0.0.1:8545 --keyfile /tmp/alice.json evm-balance
sango-wallet --rpc 127.0.0.1:8545 evm-balance 0xcccc…

evm-call — eth_call (read-only)
bash

sango-wallet --rpc 127.0.0.1:8545 \
    evm-call --to 0xcontract --data 0xdeadbeef --value 0x0

Affiche la donnée de retour en hex.
evm-sign — produire une tx signée
bash

sango-wallet --rpc 127.0.0.1:8545 --keyfile /tmp/alice.json \
    evm-sign --to 0xbbbb… --value 0x64 \
             --tx-type 1559 --gas 21000 \
             --data 0x

Sort le raw hex de la tx Ethereum typée (0x00… Legacy, 0x01…
EIP-2930, 0x02… EIP-1559). Utilisable avec eth_sendRawTransaction
d'un RPC Ethereum standard, ou avec notre propre eth_sendRawTransaction.

--tx-type accepte legacy, 2930, 1559 (défaut 1559).
Gestion du keyfile
Format v1 (clair, legacy)
json

{
  "version": 1,
  "seed_hex": "…",
  "address_hex": "…",
  "created_at": 1700000000,
  "evm_secret_hex": null
}

Non sécurisé. Un warning est émis au chargement. Chiffre-le.
Format v2 (chiffré, recommandé)
json

{
  "version": 2,
  "created_at": 1700000000,
  "address_hex": "…",
  "kdf": "argon2id",
  "kdf_params": { "m_cost_kib": 65536, "t_cost": 3, "p_cost": 4, "salt_hex": "…" },
  "cipher": "chacha20poly1305",
  "nonce_hex": "…",
  "ciphertext_hex": "…"
}

    KDF : Argon2id (m=64 MiB, t=3, p=4, OWASP 2024).

    Chiffrement : ChaCha20-Poly1305.

    Métadonnées (KDF params, cipher) en AAD : toute modification externe
    casse le déchiffrement.

keyfile-encrypt
bash

sango-wallet --keyfile /tmp/alice.json keyfile-encrypt

Chiffre un v1 en place. Passphrase demandée deux fois.

La passphrase n'est pas récupérable. Sauvegarde-la ou perds ton wallet.
keyfile-decrypt
bash

sango-wallet --keyfile /tmp/alice.json keyfile-decrypt

⚠️ Écrit la seed en clair. Usage migratoire uniquement.
keyfile-info
bash

sango-wallet --keyfile /tmp/alice.json keyfile-info

Affiche version, adresse, timestamp, et si chiffré : KDF + cipher.
Variables d'environnement
Variable	Rôle
HOME	Pour calculer ~/.sango/wallet.json
SANGO_WALLET_PASSPHRASE	Passphrase keyfile v2 (sinon prompt)
Erreurs fréquentes
Message	Cause	Fix
keyfile already exists	new sur un fichier existant	Supprime ou change --keyfile
invalid passphrase	Mauvaise passphrase, ou JSON externe modifié	Vérifie la passphrase, retape keyfile-info
insufficient balance	Solde insuffisant	Demande au faucet
missing flag --to	Flag obligatoire oublié	Ajoute --to 0x…
rpc error [-32602]	Paramètre mal formé	Vérifie l'adresse, le montant
Voir aussi

    RPC — pour appeler en direct

    Faucet — pour créditer un compte

    Devnet — pour comprendre le Genesis