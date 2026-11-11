# Design technique — E1 (EVM vertical)


## 11. Dettes tracées

### D-NET-2 — Refonte `Network` (reporté au patch 5)

**Contexte.** Deux types `Network` coexistent dans le codebase :

| Origine | Type | Sémantique |
|---|---|---|
| `@sango/types` | `"mainnet" \| "testnet"` | Label SANGO pour le HRP bech32m |
| `wallet-chains` | `{ id, family, chainId, ... }` | Descripteur multi-chaîne |

**Impact.** `StoredWalletV2.network` (patch 1.b) utilise le premier
type (`"testnet"` en placeholder) pour satisfaire
`KeyringEntry.network`. Un wallet BIP-39 (EVM) n'a **pas** de réseau
SANGO — la valeur est donc sémantiquement fausse.

**Résolution prévue (patch 5).** Deux pistes :

1. Introduire un `WalletNetwork` discriminant :
   type WalletNetwork =
     | { format: "sango-legacy"; sangoLabel: "mainnet" | "testnet" }
     | { format: "bip39";        networkId: string };

   Impact : `StoredWallet`, `KeyringEntry`, `wallet-store`.

2. Renommer `@sango/types.Network` en `SangoNetworkLabel`
   (clarification) + introduire un `networkId: string` générique dans
   le keyring.

**Justification du report.** Le patch 5 touche de toute façon le
keyring et `wallet-store`. C'est le bon moment pour faire la refonte
avec un cas d'usage réel.
