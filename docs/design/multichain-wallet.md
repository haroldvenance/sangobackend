# Design — Wallet multi-chain Sango (V2)

- **Statut** : **validé — W1 fermé**, v0.2.1
- **Auteur** : équipe backend Sango
- **Date** : 2026-09-28
- **Impact** : `sango-crypto`, `sango-wallet`, frontend
- **Non-impact** : `sango-node`, `sango-rpc`, `sango-explorer`, `sango-faucet`

## Résumé

Transformer `sango-wallet` en wallet **multi-chain** basé sur **BIP-39**
(mnemonic) + **dérivation HD standardisée** par chaîne, tout en
préservant strictement la compatibilité des wallets existants (keyfiles
V1 et V2) et le format natif Sango (`sango1…` / `tsango1…`).

**Principe non négociable** : aucune cryptographie propriétaire. On
s'appuie sur BIP-39, BIP-32 (secp256k1) et SLIP-0010 (Ed25519), avec des
crates audités.

## Motivation

État actuel :

```text
seed 32 bytes (Ed25519)
       │
       ▼
NativeKeypair (Ed25519)
       │
       ▼
Keccak256("SANGO/ADDRESS/V1" || pk)[0..20]
       │
       ▼
sango1… / tsango1…

Cette architecture est correcte pour Sango natif V1, mais :

    Pas de backup standard : l'utilisateur doit sauvegarder 32 bytes
    bruts, sans mécanisme de vérification (checksum, mnemonic).

    Pas d'interop : impossible d'importer la même seed dans MetaMask,
    Phantom, Ledger.

    Pas de multi-chain : ajouter BTC/ETH/SOL nécessiterait des seeds
    séparées, multipliant les backups.

Objectif : un seed maître unique (mnemonic), dérivant des clés
indépendantes par chaîne, avec les standards de l'industrie.
Décisions
D1 — BIP-39 comme seed maître

Décision : la mnemonic BIP-39 (12 ou 24 mots, anglais) est la
source unique de toute dérivation dans le wallet V3.

Dérivation : PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" || passphrase, 2048 itérations, 64 bytes) → seed.

Passphrase BIP-39 (25ᵉ mot) : supportée dès le V1 de V3, y
compris si l'UI ne l'expose pas immédiatement. L'API interne doit
prendre un paramètre passphrase: Option<&str>, défaut None = chaîne
vide. Rétro-ajouter une passphrase après coup est impossible sans casser
toutes les dérivations.

Langue : anglais uniquement en V1. L'encodage de la mnemonic est
toujours anglais, quelle que soit la langue d'affichage. Un
utilisateur français reçoit une mnemonic en anglais.

Longueur : 24 mots recommandé (256 bits d'entropie). 12 mots
accepté (128 bits) pour la compatibilité avec les wallets qui
n'utilisent que 12.

Crate : bip39 (rust-bitcoin). Audité, stable, golden vectors
officiels.
D2 — BIP-32 (secp256k1) vs SLIP-0010 (Ed25519)

Décision : deux algorithmes de dérivation distincts, un par
famille de courbe.
Courbe	Standard	Chaînes concernées
secp256k1	BIP-32	BTC, EVM (ETH, BSC, Polygon…), LTC
Ed25519	SLIP-0010	SOL, Sango natif, Cardano, Tezos

Justification : BIP-32 spécifie une dérivation pour courbes à
structure de groupe (secp256k1), pas pour Ed25519. SLIP-0010 est le
standard de facto pour Ed25519 HD, approuvé par SatoshiLabs.

Schéma corrigé :
text

                BIP-39 mnemonic (12/24 mots)
                        │
                  PBKDF2 (2048 it.)
                        │
                        ▼
                   seed 64 bytes
                        │
        ┌───────────────┴───────────────┐
        │                               │
        ▼                               ▼
    BIP-32                          SLIP-0010
  (secp256k1)                       (Ed25519)
        │                               │
  ┌─────┼─────┐                  ┌──────┼──────┐
  ▼     ▼     ▼                  ▼      ▼      ▼
 BTC   ETH   LTC               SOL   Sango  (futur)

Aucune chaîne Ed25519 ne passe par BIP-32. Aucune chaîne secp256k1 ne
passe par SLIP-0010.

Crates :

    BIP-32 : bip32 (rust-bitcoin).

    SLIP-0010 : slip10 (crate autonome) ou implémentation locale basée
    sur hmac + sha2 + ed25519-dalek. Décision : slip10 d'abord,
    revue formelle en début de W3. Si le crate amont ne satisfait pas la
    revue (maintenance, qualité, golden vectors), bascule sur
    implémentation locale.

D3 — Chemins de dérivation par chaîne

Décision : chemins standards par coin type.
Chaîne	Courbe	Chemin	Standard
Sango	Ed25519	m/44'/COIN'/0'/0'/0'	SLIP-0010, tous hardened
Bitcoin	secp256k1	m/84'/0'/0'/0/0	BIP-84 (native SegWit)
Ethereum	secp256k1	m/44'/60'/0'/0/0	BIP-44
Solana	Ed25519	m/44'/501'/0'/0'	SLIP-0010, tous hardened

Règle hardened (clarification) :

Sur Ed25519 (SLIP-0010), tous les niveaux de dérivation sont
hardened. C'est une contrainte de la courbe : la dérivation
non-hardened n'est pas définie pour les courbes Edwards. La notation
/0' signifie hardened.

Conséquence sur Solana : le chemin m/44'/501'/0'/0' comporte
4 niveaux hardened :
text

m  /  44'  /  501'  /  0'  /  0'
   ^^^^    ^^^^^    ^^^    ^^^
   hardened hardened hardened hardened

Ce chemin est celui utilisé par Phantom, Solflare et les wallets
Solana de référence. Golden vector obligatoire : dériver une adresse
Solana depuis une mnemonic connue et vérifier qu'elle correspond
byte-à-byte à celle produite par Phantom pour la même mnemonic
(index 0). Sans ce test, on n'est pas compatible.

Conséquence sur Sango : m/44'/COIN'/0'/0'/0' = 5 niveaux
tous hardened.

Bitcoin : BIP-84 (native SegWit, bc1…) est le défaut moderne.
BIP-44 (legacy, 1…) et BIP-49 (P2SH, 3…) ne sont pas
supportés en V1.
D4 — Coin type Sango : règles strictes par réseau

Problème : on ne peut pas figer <SANGO_COIN_TYPE> tant qu'il n'est
pas officiellement enregistré dans SLIP-0044. Une erreur ici casse la
restauration des wallets.

Décision — règles strictes :
Réseau	Coin type	Wallet V3 autorisé	Notes
Devnet	100001	✅	Usage local, jetable
Testnet	100001	✅	Public, jetable
Mainnet	TBD	❌	Aucun wallet mainnet V3 avant décision finale

Règles absolues :

    Le binaire sango-wallet compilé en mode mainnet ne doit jamais
    utiliser 100001 par défaut. Si un utilisateur tente de créer un
    wallet V3 sans avoir explicitement configuré un coin type mainnet
    (une fois celui-ci décidé), le binaire refuse avec un message
    explicite.

    Aucun wallet V3 mainnet ne doit être distribué publiquement tant
    que le coin type n'est pas définitivement figé.

    La configuration réseau est explicite : le binaire est compilé ou
    lancé avec --network mainnet|testnet|devnet. Le coin type effectif
    dépend de cette configuration. Pas de fallback silencieux.

    Une fois le coin type mainnet attribué, il est immuable. Toute
    PR ultérieure qui tenterait de le changer doit être rejetée en bloc.

Stratégie d'obtention du coin type mainnet :

Option A (long terme, retenue) : ouvrir une PR SLIP-0044 une
fois le testnet public stable. Délai : plusieurs semaines/mois, hors de
notre contrôle. Une fois attribué, on fige.

Option B (repli) : décision collégiale d'utiliser un coin type dans
une zone non conflictuelle, documenté publiquement. Utilisée seulement
si SLIP-0044 refuse ou traîne indéfiniment.

Note : le coin type n'apparaît jamais dans une transaction ou
dans le protocole. C'est purement local au wallet. Aucun impact
consensus.
D5 — Versionnage du keyfile

Décision : trois formats coexistent, avec sémantique stricte.
Version	Contenu	Statut	Actions supportées
V1	Seed Ed25519 (32 bytes) chiffrée	legacy	Lecture seule
V2	Idem V1 + métadonnées	courant	Lecture + écriture
V3	Mnemonic BIP-39 + passphrase + métadonnées	nouveau	Lecture + écriture

Règles :

    V1 et V2 restent lisibles indéfiniment. Les wallets existants ne
    cassent jamais.

    Aucune migration automatique V2 → V3. Un wallet V2 qui contient
    des fonds ne se met pas à jour en place. L'utilisateur crée un
    nouveau wallet V3 et transfère.

        Justification : une migration en place qui modifie la seed
        invaliderait tous les backups papier existants.

    Détection automatique au chargement (champ version en clair).

    Refus explicite si le fichier est ouvert avec le mauvais parser.

D6 — Représentation en mémoire : mnemonic, pas seed

Décision : l'état canonique du wallet V3 en mémoire est la
mnemonic + passphrase, pas le seed BIP-39 dérivé.

Justification :

    La mnemonic est ce que l'utilisateur a sauvegardé. Le seed est un
    matériel dérivé, jetable.

    Garder la mnemonic permet de changer de passphrase, de re-dériver
    à volonté, de vérifier la saisie utilisateur.

    La transformation (mnemonic, passphrase) → seed est déterministe
    et reproductible : les mêmes entrées produisent toujours le même
    seed. Elle n'est pas réversible : à partir du seed seul, on ne
    peut retrouver ni la mnemonic ni la passphrase. C'est cette asymétrie
    qui justifie de conserver la mnemonic comme secret canonique.

Représentation :
rust

use zeroize::Zeroizing;

pub struct WalletV3 {
    /// Mnemonic BIP-39 (anglais, 12 ou 24 mots).
    /// `Zeroizing` garantit l'effacement mémoire au Drop.
    mnemonic: Zeroizing<String>,
    /// Passphrase BIP-39 optionnelle (25ᵉ mot). Jamais persistée.
    passphrase: Option<Zeroizing<String>>,
}

impl WalletV3 {
    /// Dérive le seed BIP-39 (64 bytes) à la demande.
    /// Retourne `Zeroizing<[u8; 64]>` : effacé après usage.
    fn bip39_seed(&self) -> Result<Zeroizing<[u8; 64]>, WalletError> {
        // PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" || passphrase, 2048, 64)
        // ...
    }

    /// Dérive la clé native Sango à l'index d'account donné.
    pub fn sango_keypair(&self, account_index: u32) -> Result<NativeKeypair, WalletError> {
        let seed = self.bip39_seed()?;
        // SLIP-0010 sur m/44'/COIN'/0'/0'/account'
        // ...
    }

    /// Dérive la clé EVM à l'index d'account donné.
    pub fn evm_keypair(&self, account_index: u32) -> Result<Secp256k1Keypair, WalletError> {
        let seed = self.bip39_seed()?;
        // BIP-32 sur m/44'/60'/0'/0/account
        // ...
    }
}

Contraintes :

    Aucune méthode publique n'expose le seed. Le seed est calculé
    à la demande, utilisé, et effacé.

    Zeroizing (crate zeroize, déjà en deps) efface la mémoire au Drop.

    Le keyfile V3 chiffré ne contient pas le seed non plus : seulement
    la mnemonic chiffrée.

    Un Debug custom ne doit jamais afficher la mnemonic ni la
    passphrase ("<redacted>").

D7 — Spécification cryptographique du keyfile V3

Décision : spécification stricte, figée, testée par golden vector.
D7.1 — Paramètres Argon2id
Paramètre	Valeur V1	Justification
algorithm	Argon2id	RFC 9106, recommandé
m_cost	65536 KiB (64 MiB)	OWASP 2024
t_cost	3	OWASP 2024
p_cost	4	défaut
output_len	32 bytes	longueur de clé ChaCha20
salt_len	32 bytes	aléatoire, non secret

Le sel est généré par OsRng (crate rand_core avec feature getrandom).
Un sel unique par keyfile, jamais réutilisé, jamais dérivé de
l'adresse ou du label.
D7.2 — Chiffrement ChaCha20-Poly1305
Paramètre	Valeur V1
cipher	ChaCha20-Poly1305 (IETF, RFC 8439)
nonce_len	12 bytes
tag_len	16 bytes (inclus dans le ciphertext)
aad	b"sango-wallet-v3" (16 bytes ASCII)

Nonce généré par OsRng, unique par chiffrement. En pratique, le
keyfile est réécrit rarement (création, changement de label), donc un
compteur n'est pas nécessaire.

AAD : lie le chiffrement à la version de format. Une tentative de
déchiffrer un ciphertext V3 comme un V2 échoue au tag Poly1305.
D7.3 — Plaintext avant chiffrement

Encodage : JSON canonique (UTF-8, sans espaces superflus). Ce format
est choisi pour la lisibilité en debug et parce que le tag Poly1305
détecte toute altération.

Structure :
json

{
  "mnemonic": "word1 word2 … word24",
  "bip39_passphrase_used": false,
  "next_account_index": 0
}

Champs :
Champ	Type	Description
mnemonic	string	12 ou 24 mots anglais, séparés par un espace unique
bip39_passphrase_used	bool	PAS la passphrase, juste un booléen
next_account_index	u32	prochain index d'account (réservé pour V4)

Invariant : le plaintext ne contient jamais : seed, clé privée,
passphrase, mot de passe de chiffrement, données d'autres chaînes.
D7.4 — Format du fichier V3
json

{
  "version": 3,
  "kdf": {
    "algo": "argon2id",
    "m_cost": 65536,
    "t_cost": 3,
    "p_cost": 4,
    "output_len": 32,
    "salt_hex": "0x…"
  },
  "cipher": {
    "algo": "chacha20poly1305",
    "aad": "sango-wallet-v3",
    "nonce_hex": "0x…"
  },
  "ciphertext_hex": "0x…",
  "meta": {
    "created_at": 1700000000,
    "label": "Mon wallet",
    "chains": ["sango", "btc", "evm", "sol"]
  }
}

Tous les champs binaires (salt_hex, nonce_hex, ciphertext_hex)
sont hex avec préfixe 0x. Le ciphertext inclut les 16 bytes de tag
Poly1305 en suffixe (convention ChaCha20-Poly1305 IETF).

Champs en clair (non chiffrés) : version, kdf, cipher,
meta. Un attaquant peut lire ces métadonnées, ce qui est acceptable
(elles n'aident pas à casser le chiffrement).

Champs chiffrés : uniquement ciphertext_hex.

Format retenu : JSON canonique. Justification : inspectable,
versionnable, testable byte-à-byte, portable Rust ↔ TypeScript/WASM.
Le secret reste entièrement dans ciphertext_hex.
D7.5 — Golden vector V6 (keyfile V3 complet)

Obligatoire en W4. Vecteur figé :
text

Input :
  password    = "correct horse battery staple"
  mnemonic    = "abandon abandon … about"  (12 mots, test vector BIP-39)
  passphrase  = "" (vide, donc bip39_passphrase_used = false)
  salt        = 0x000102…1f (32 bytes, fixés pour le test)
  nonce       = 0x000102…0b (12 bytes, fixés pour le test)
  label       = "test-wallet"
  created_at  = 1700000000

Output :
  ciphertext_hex = 0x<hex attendu, ~180 bytes>
  fichier JSON   = <JSON attendu, byte-à-byte>

Roundtrip :
  decrypt(fichier, "correct horse battery staple") → mnemonic identique
  decrypt(fichier, "mauvais password") → tag mismatch
  decrypt(fichier, "") → tag mismatch

Ce test garantit que deux implémentations (Rust natif, WASM frontend)
produisent exactement le même fichier.
D8 — Compatibilité native Sango V1

Décision : la formule actuelle ne change pas.
text

native_keypair = Ed25519(seed_v1_ou_dérivée)
native_address = Keccak256("SANGO/ADDRESS/V1" || native_public_key)[0..20]

Ce qui change : la provenance de la clé privée Ed25519.

    Wallet V2 : la seed de 32 bytes est la clé privée Ed25519.

    Wallet V3 : la clé privée Ed25519 est dérivée du seed BIP-39 via
    SLIP-0010 (chemin m/44'/COIN'/0'/0'/0').

Conséquence : pour la même mnemonic, un wallet V3 donne une adresse
Sango différente de celle qu'on aurait eue en utilisant la seed
directement. Ce n'est pas un problème, car aucune migration V2 → V3
n'est prévue (voir D5).

Golden vector à produire : mnemonic connue + chemin Sango + adresse
tsango1… attendue. Voir section Vecteurs.
Séparation backend / frontend

Décision : frontière stricte, contrats explicites.
text

┌─────────────────────────────────────────────────────────────┐
│ Backend / wallet-core (Rust, sango-crypto + sango-wallet)   │
│                                                              │
│  Produit :                                                   │
│    • mnemonic BIP-39 (génération, validation)                │
│    • dérivation BIP-32 / SLIP-0010                           │
│    • keyfile V3 (spec D7)                                    │
│    • signatures Ed25519 (Sango natif)                        │
│    • signatures secp256k1 (EVM)                              │
│    • golden vectors CI                                       │
│                                                              │
│  Contrats exposés au frontend :                              │
│    • créer une mnemonic  → [String]                          │
│    • valider une mnemonic → bool                             │
│    • dériver adresse Sango à l'index N → "tsango1…"          │
│    • dériver adresse EVM à l'index N  → "0x…"                │
│    • signer tx native → bytes                                │
│    • signer tx EVM    → bytes                                │
│    • créer un keyfile V3 → bytes JSON                        │
│    • ouvrir un keyfile V3 → WalletV3                         │
└─────────────────────────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│ Frontend (TypeScript)                                        │
│                                                              │
│  Possède :                                                   │
│    • UX onboarding mnemonic (affichage, vérification)        │
│    • UX import / restore                                     │
│    • UX verrouillage / déverrouillage                        │
│    • préférences utilisateur                                 │
│    • affichage des comptes                                   │
│                                                              │
│  Ne possède PAS :                                            │
│    • d'implémentation cryptographique                        │
│    • de copie de la logique de dérivation                    │
└─────────────────────────────────────────────────────────────┘

Règles :

    Le frontend n'implémente aucune primitive cryptographique. Il
    consomme wallet-core via WASM (ou via un service local pour les
    desktop wallets). Toute dérivation, signature, chiffrement passe par
    wallet-core.

    Golden vectors partagés : les vecteurs BIP-39, BIP-32, SLIP-0010
    et Sango doivent être testés côté TS et côté Rust, sur exactement
    les mêmes inputs, avant tout développement frontend V3.

    Aucun développement frontend V3 avant W5 (golden vectors + interop
    validés). C'est une contrainte ferme : si le backend produit une
    adresse erronée, mieux vaut le découvrir en CI Rust qu'en UX mnemonic.

Paramètres frontend déjà décidés (note de coordination) :

    L'écran « Paramètres » est le conteneur principal.

    Une section « Préférences » séparée de « Sécurité / Wallet ».

    On ne commence pas l'onboarding mnemonic tant que W5 n'est pas vert.

Alternatives rejetées
A1 — Réutiliser la seed Ed25519 comme seed universelle

Rejet : Ed25519 n'est pas un KDF. Aucun wallet du marché
n'accepterait de restaurer depuis cette seed. Empêche la séparation des
clés.
A2 — Un seul chemin pour toutes les chaînes Ed25519

Rejet : casse la séparation des clés. Une fuite Sango affecte SOL.
Non-standard.
A3 — BIP-44 (legacy) pour Bitcoin

Rejet : BIP-84 (native SegWit) est le standard moderne.
A4 — Stocker la passphrase BIP-39 dans le keyfile

Rejet : détruit la protection contre la compromission du seul
fichier.
A5 — Migration en place V2 → V3

Rejet : invalide tous les backups papier.
A6 — Stocker le seed (64 bytes) au lieu de la mnemonic

Rejet : le seed est dérivé, non réversible vers la mnemonic. Perte
de flexibilité (changement de passphrase, vérification de saisie). Voir
D6.
Golden vectors

Chaque vecteur est un test #[test] en Rust + un test équivalent TS,
avec valeurs figées.
ID	Couverture	Source	Bloquant pour
V1	BIP-39 standard	vecteurs Trezor officiels	CI
V2	BIP-32 standard	vecteurs officiels BIP-32	CI
V3	SLIP-0010 Ed25519 standard	vecteurs officiels SLIP-0010	CI
V4A	Sango natif depuis mnemonic	produit par nous	W4
V4B	EVM depuis mnemonic	produit par nous	W4
V4C	Solana depuis mnemonic	produit par nous + Phantom	W4
V6	Keyfile V3 complet	produit par nous (spec D7.5)	W4
V7	Interop MetaMask / Phantom	manuel	W5

Contrainte : V1, V2, V3 doivent passer avant tout développement
W2/W3. V4A/B/C et V6 doivent passer avant W5.
Plan de test interop
Test	Outil	Critère	Fréquence
BIP-39	bip39	Vecteurs Trezor	CI
BIP-32	bip32	Vecteurs officiels	CI
SLIP-0010	slip10	Vecteurs officiels	CI
Sango native	golden V4A	Adresse tsango1… attendue	CI
Sango EVM	golden V4B	Adresse 0x… attendue	CI
Solana	golden V4C	Adresse base58 attendue	CI
Interop MetaMask	manuel	Adresse EVM identique à MM	1× post-W5
Interop Phantom	manuel	Adresse SOL identique à Phantom	1× post-W5
Interop Ledger	—	Hors scope V1	—
Ce qu'on ne fait pas en V1
NG1 — Ledger native app

Publier une app Sango sur LedgerHQ/apps : plusieurs mois, hors scope.
NG2 — Multi-account HD

V1 supporte un seul account par chaîne (/0'/0/0 ou /0'/0'/0').
Le multi-account propre (changement d'index, UI de sélection) est un
chantier UX à part. Réservé V4.
NG3 — Langues de mnemonic autres que l'anglais

Anglais uniquement. Une mnemonic française ne se restaure pas dans
MetaMask. L'UI peut traduire les mots pour l'autocomplete, la valeur
canonique reste anglaise.
NG4 — Watch-only wallets

Pas d'import d'adresse sans clé privée.
NG5 — Multi-sig

Pas de multisig natif. Contrat EVM (Safe) si besoin.
NG6 — Signer distant / HSM

Pas de Web3Signer, PKCS#11, etc.
NG7 — Backup cloud

Backup = mnemonic papier. Point.
NG8 — Migration automatique V2 → V3

Refus explicite.
NG9 — BTC testnet / regtest

BTC mainnet uniquement.
NG10 — Autres EVM chains

Ethereum mainnet seul dans le chemin explicite. BSC/Polygon/Arbitrum
partagent m/44'/60'/… : pas de travail supplémentaire, juste un
RPC différent.
Plan d'implémentation
Étape	Contenu	Effort	Bloqueur
W1	Design doc (v0.1 → v0.2.1)	2h	—
W2	sango-crypto::mnemonic (BIP-39) + V1	4h	W1
W3	sango-crypto::hd (BIP-32 + SLIP-0010) + V2, V3	6h	W2
W4	keyfile V3 + CLI + golden V4A/B/C, V6	8h	W3
W5	Interop MetaMask / Phantom (manuel)	4h	W4
W6	Frontend onboarding mnemonic	1 sem	W5

Total backend : ~24h.

Contrainte globale : aucune implémentation W2–W6 avant validation de
W1 (ce doc, v0.2.1). Aucun développement frontend V3 avant W5 vert.
Décisions W1 (fermées)

Les 5 points ouverts ont été tranchés en revue de W1.
#	Point	Décision	Notes
1	Coin type mainnet	SLIP-0044 en priorité (Option A)	PR ouverte dès le testnet public stable. Repli collégial (Option B) uniquement si SLIP-0044 refuse ou traîne indéfiniment.
2	Crate SLIP-0010	slip10 d'abord, revue avant adoption	Si le crate amont ne satisfait pas la revue (maintenance, qualité, golden vectors), bascule sur implémentation locale hmac + sha2 + ed25519-dalek. Revue formelle en début de W3.
3	Support 12 vs 24 mots	Les deux, 24 par défaut	24 recommandé par l'UI, 12 accepté pour compatibilité. La validation BIP-39 accepte indifféremment.
4	Format keyfile V3	JSON canonique	Format inspectable, portable Rust ↔ TS/WASM, byte-à-byte testable. Le secret reste entièrement dans ciphertext_hex (spec D7.4).
5	Auto-détection CLI	Oui, pas de flag --format	Le champ version en clair est lu au chargement, le parser est choisi automatiquement. Un flag explicite serait une source d'erreur (mismatch silencieux).

Ces décisions sont verrouillées : toute modification ultérieure
nécessite un nouveau passage en revue W1 et une mise à jour de ce
document.
Références

    BIP-32 — HD Wallets
    https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

    BIP-39 — Mnemonic code
    https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

    BIP-44 — Multi-Account Hierarchy
    https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki

    BIP-84 — Native SegWit
    https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki

    SLIP-0010 — Universal private key derivation
    https://github.com/satoshilabs/slips/blob/master/slip-0010.md

    SLIP-0044 — Registered coin types
    https://github.com/satoshilabs/slips/blob/master/slip-0044.md

    RFC 9106 — Argon2
    https://datatracker.ietf.org/doc/html/rfc9106

    RFC 8439 — ChaCha20-Poly1305
    https://datatracker.ietf.org/doc/html/rfc8439

Historique
Date	Version	Changement
2026-09-28	0.1	Version initiale
2026-09-28	0.2	Intègre les retours de revue : D4 règles strictes par réseau, D6 (mnemonic en mémoire), D7 (spec keyfile), clarification D3 hardened, section séparation backend/frontend
2026-09-28	0.2.1	Corrections finales + fermeture des points ouverts :
— D6 : « réversible » remplacé par « déterministe et reproductible », précise que seed → mnemonic est impossible
— Section « Décisions W1 (fermées) » : SLIP-0044, slip10, 12+24 (24 par défaut), JSON canonique, auto-détection CLI
