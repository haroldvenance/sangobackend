# Testing interop — MetaMask / Phantom

- **Statut** : vivant
- **Couvre** : W5 du plan multi-chain (`docs/design/multichain-wallet.md`)
- **Portée** : procédure manuelle, exécutée une fois par release de
  `sango-wallet` qui touche à la dérivation HD.

## Objectif

Vérifier que `sango-wallet` V3 produit, à partir d'une mnemonic BIP-39,
les **mêmes clés** que les wallets multi-chain de référence :

| Chaîne | Référence externe | Chemin HD |
|---|---|---|
| Ethereum | MetaMask, Anvil, Hardhat, ethers.js | `m/44'/60'/0'/0/0` |
| Solana | Phantom | `m/44'/501'/0'/0'` |

Un écart sur cette procédure = **hard fork de wallet**. Il faut le
documenter et coordonner avec le frontend.

## Golden vectors de référence

Ces vecteurs sont dans `crates/sango-wallet/tests/wallet_v3_golden.rs`.

### V4A — BIP-39 officiel

Mnemonic :

    abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about

Adresse Sango devnet (`m/44'/100001'/0'/0'/0'`) :

    tsango13ujlkt9hdx7spcausd8a7wd0n63spscumvc32s

Adresse EVM (`m/44'/60'/0'/0/0`), checksum EIP-55 :

    0x9858EfFD232B4033E47d90003D41EC34EcaEda94

### V4B — Hardhat / Anvil

Mnemonic :

    test test test test test test test test test test test junk

Adresse EVM (`m/44'/60'/0'/0/0`), checksum EIP-55 :

    0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266

Valeur **publiquement connue** (Hardhat, Anvil, Foundry, ethers.js par
défaut). Le test `golden_v4b_evm_address_hardhat` l'assert
directement.

Adresse Sango devnet (`m/44'/100001'/0'/0'/0'`) :

    tsango1882fg6lw3swwygtvvn47hgjnacxz9rr55agjlz

### V6 — Keyfile V3

Vecteur byte-à-byte dans `crates/sango-wallet/src/keystore_v3.rs`
(module `golden_v6`). Voir `golden_v6::print`.

## Test MetaMask — procédure

### 1. Préparer un wallet V3 de test

    cargo run -p sango-wallet -- --keyfile /tmp/test.json new --bip39 --words 12

Puis exporter la mnemonic :

    cargo run -p sango-wallet -- --keyfile /tmp/test.json export-mnemonic

Noter la mnemonic et l'adresse EVM affichée par :

    cargo run -p sango-wallet -- --keyfile /tmp/test.json evm-address

### 2. Importer dans MetaMask

1. Ouvrir MetaMask → menu → **Import account**.
2. Choisir **Import using Secret Recovery Phrase**.
   Attention : cela **remplace** le wallet courant. Utiliser un
   profil navigateur dédié ou un MetaMask vide.
3. Coller la mnemonic, valider.
4. MetaMask affiche une adresse Ethereum.

### 3. Comparer

L'adresse MetaMask (account 1, chemin par défaut) doit être
**byte-à-byte identique** (insensible à la casse) à celle affichée
par `sango-wallet evm-address`.

Si divergence :

- Vérifier que MetaMask n'utilise pas un chemin custom
  (Settings → Advanced → Custom derivation path) — doit être vide
  ou `m/44'/60'/0'/0`.
- Vérifier qu'on est sur la même version BIP-44 (stable depuis 2016).

### 4. Comparer les signatures (optionnel)

Produire une tx EVM signée avec `sango-wallet evm-sign` :

    cargo run -p sango-wallet -- --keyfile /tmp/test.json evm-sign \
        --to 0x0000000000000000000000000000000000000001 \
        --value 1 --tx-type 1559

Les signatures secp256k1 étant déterministes (RFC 6979), les bytes
signés doivent être **identiques** pour le même nonce, gas, etc.

## Test Phantom — doc-only en V1

sango-wallet V3 ne supporte pas encore Solana. Section documentée
pour une itération W5-ext ultérieure.

Cible : chemin `m/44'/501'/0'/0'` (SLIP-0010, tous hardened),
adresse `Base58(ed25519_pubkey)`.

## Test Ledger — hors scope V1

Publier une app Sango sur LedgerHQ/apps prend plusieurs mois
(développement + audit + revue). Hors périmètre V1.

## Critères de succès

| Test | Critère | Fréquence |
|---|---|---|
| V4A Sango | `tsango13ujlkt9hdx7spcausd8a7wd0n63spscumvc32s` | CI |
| V4A EVM | `0x9858EfFD232B4033E47d90003D41EC34EcaEda94` | CI |
| V4B EVM | `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266` | CI |
| V4B Sango | `tsango1882fg6lw3swwygtvvn47hgjnacxz9rr55agjlz` | CI |
| V6 keyfile | byte-à-byte | CI |
| MetaMask interop | adresse EVM identique | 1× par release qui touche HD |
| Phantom interop | (à faire) | — |
| Ledger | — | hors scope V1 |

## Comment régénérer les adresses

    cargo test -p sango-wallet --test wallet_v3_golden print_golden -- --nocapture
    cargo test -p sango-wallet --test wallet_v3_golden print_golden_2 -- --nocapture
    cargo test -p sango-wallet golden_v6::print -- --nocapture

## Checklist avant release

- [ ] `cargo test --workspace` vert.
- [ ] `golden_v4a_evm_address` vert.
- [ ] `golden_v4b_evm_address_hardhat` vert (validation externe).
- [ ] `golden_v6::json_matches_golden` vert.
- [ ] MetaMask interop exécuté manuellement (si HD touché).
- [ ] `docs/design/multichain-wallet.md` à jour si un chemin change.
