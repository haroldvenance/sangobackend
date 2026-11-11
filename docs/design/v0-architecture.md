```bash
mkdir -p docs/design
```

# Document final : `docs/design/v0-architecture.md`

```markdown
# Design technique — V0 (architecture-first, SANGO only)

- **Statut** : v0.1, à valider
- **Parent** : `docs/design/vision-multichain.md` (D1–D10 validées)
- **Portée** : refonte architecturale. **Aucune nouvelle chaîne**.
- **Critère d'acceptation** : SANGO fonctionne inchangé à travers la
  nouvelle architecture ; tous les tests existants passent.
- **Non-objectif** : ajouter EVM, BTC, SOL, tokens, NFT.

---

## 1. Principe directeur

V0 introduit des **frontières stables** entre :

- **clés / dérivation / signature** (`wallet-core`)
- **logique des chaînes** (`wallet-chains`)
- **accès aux données** (`wallet-providers`)
- **orchestration** (`wallet-session`)
- **présentation** (`apps/wallet`)

L'objectif de V0 n'est pas d'ajouter une chaîne, c'est de **rendre
l'ajout d'une chaîne non-douloureux**.

```
┌────────────────────────────────────────────────┐
│                  apps/wallet                   │
└───────────────────┬────────────────────────────┘
                    │
┌───────────────────▼────────────────────────────┐
│               wallet-session                   │
│   WalletSession · Accounts · Assets            │
└───────┬──────────────────────────┬─────────────┘
        │                          │
┌───────▼─────────────┐  ┌─────────▼───────────┐
│    wallet-core      │  │    wallet-chains    │
│                     │  │                     │
│ mnemonic            │  │ ChainRegistry       │
│ derivation          │  │ capabilities        │
│ Signer              │  │ sango/              │
│ storage / keyring   │  │                     │
└─────────────────────┘  └─────────┬───────────┘
                                   │
                         ┌─────────▼───────────┐
                         │  wallet-providers   │
                         │ rpc · indexers ·    │
                         │ explorers           │
                         └─────────────────────┘
```

---

## 2. Arborescence cible

```
frontend/packages/
├── wallet-core/                     (refactor mineur)
│   └── src/
│       ├── keys/
│       │   ├── mnemonic.ts          (existant)
│       │   ├── seed.ts              (existant)
│       │   └── keypair.ts           (existant)
│       ├── derivation/
│       │   ├── scheme.ts            (NOUVEAU — DerivationScheme)
│       │   ├── path.ts              (NOUVEAU — DerivationPath)
│       │   ├── sango.ts             (NOUVEAU — chemin 44'/100001'…)
│       │   └── index.ts
│       ├── signing/
│       │   ├── signer.ts            (NOUVEAU — interface Signer)
│       │   ├── ed25519-signer.ts    (NOUVEAU — implémentation)
│       │   └── index.ts
│       ├── storage/                 (existant)
│       ├── keyring/                 (existant)
│       └── index.ts
│
├── wallet-chains/                    (NOUVEAU)
│   └── src/
│       ├── types/
│       │   ├── chain.ts             ChainFamily, ChainDescriptor
│       │   ├── network.ts           Network
│       │   ├── asset.ts             Asset, AssetRef
│       │   ├── token.ts             Token
│       │   ├── address.ts           Address
│       │   ├── balance.ts           Balance
│       │   ├── tx.ts                UnsignedTransaction, SignedTransaction
│       │   ├── history.ts           TxHistory, HistoryItem
│       │   └── index.ts
│       ├── capabilities/
│       │   ├── address-provider.ts
│       │   ├── balance-provider.ts
│       │   ├── history-provider.ts
│       │   ├── transaction-builder.ts
│       │   ├── transaction-signer.ts
│       │   ├── broadcaster.ts
│       │   ├── fee-estimator.ts
│       │   ├── token-provider.ts
│       │   └── index.ts
│       ├── registry/
│       │   ├── chain-registry.ts
│       │   └── index.ts
│       ├── sango/
│       │   ├── adapter.ts           SangoAdapter
│       │   ├── address-provider.ts
│       │   ├── balance-provider.ts
│       │   ├── history-provider.ts
│       │   ├── transaction-builder.ts
│       │   ├── transaction-signer.ts
│       │   ├── broadcaster.ts
│       │   ├── fee-estimator.ts
│       │   ├── config.ts            SANGO_DEVNET, SANGO_TESTNET
│       │   └── index.ts
│       └── index.ts
│
├── wallet-providers/                 (NOUVEAU)
│   └── src/
│       ├── rpc/
│       │   ├── rpc-pool.ts          interface RpcPool
│       │   ├── sango-rpc.ts         adapter sur @sango/sango-rpc
│       │   └── index.ts
│       ├── history/
│       │   ├── history-pool.ts      interface HistoryProviderPool
│       │   ├── sango-indexer.ts     adapter sur sango_getTransactionsByAddress
│       │   └── index.ts
│       ├── explorers/
│       │   ├── explorer-registry.ts
│       │   ├── sango-explorer.ts    config pour http://…:8090
│       │   └── index.ts
│       └── index.ts
│
├── wallet-session/                   (NOUVEAU)
│   └── src/
│       ├── session.ts               WalletSession
│       ├── accounts.ts              AccountList
│       ├── assets.ts                AssetList
│       └── index.ts
│
├── sango-rpc/                        (inchangé — client transport)
├── sango-sdk/                        (inchangé — SDK haut niveau SANGO)
├── sango-types/                      (inchangé)
│
└── apps/wallet/                      (migré pour utiliser WalletSession)
```

**Règle** : `sango-rpc` et `sango-sdk` ne sont pas touchés. Ils restent
la couche SDK SANGO. `SangoAdapter` les utilise via `wallet-providers`.

---

## 3. Interfaces TypeScript concrètes

### 3.1 `wallet-core` — types de base

```ts
// packages/wallet-core/src/derivation/scheme.ts

export type ChainFamily = "sango" | "evm" | "bitcoin" | "solana";

export interface DerivationPath {
  readonly family: ChainFamily;
  readonly account: number;
  readonly index: number;
  toString(): string;
}

export interface DerivationScheme {
  readonly family: ChainFamily;
  path(account: number, index: number): DerivationPath;
  derive(seed: Uint8Array, path: DerivationPath): DerivedKey;
}

export interface DerivedKey {
  readonly privateKey: Uint8Array;
  readonly publicKey: Uint8Array;
}
```

```ts
// packages/wallet-core/src/signing/signer.ts

export interface AccountRef {
  readonly family: ChainFamily;
  readonly accountIndex: number;
  readonly networkId?: string;
}

export interface Signer {
  /**
   * Retourne l'adresse associée à `account` pour la famille donnée.
   * L'adresse est un format opaque (string) — c'est l'adapter de
   * chaîne qui sait l'interpréter.
   */
  getAddress(account: AccountRef): Promise<string>;

  /**
   * Signe une transaction non-signée. Le payload est opaque côté
   * signer ; c'est l'adapter qui l'a produit.
   */
  sign(tx: UnsignedTransaction): Promise<SignedTransaction>;

  /**
   * Signe un message brut (pour authentification, proof-of-ownership).
   */
  signMessage(message: Uint8Array, account: AccountRef): Promise<Uint8Array>;
}
```

### 3.2 `wallet-chains` — types métier

```ts
// packages/wallet-chains/src/types/chain.ts

export type ChainFamily = "sango" | "evm" | "bitcoin" | "solana";

export interface ChainDescriptor {
  readonly family: ChainFamily;
  readonly displayName: string;
}
```

```ts
// packages/wallet-chains/src/types/network.ts

export interface Network {
  readonly id: string;              // "sango-devnet", "sango-testnet"
  readonly family: ChainFamily;
  readonly name: string;            // "Sango Devnet"
  readonly chainId: string;         // hex 32 bytes pour SANGO, u64 pour EVM
  readonly nativeAsset: AssetId;
  readonly defaultRpcEndpoints: readonly string[];
  readonly explorer?: ExplorerConfig;
}
```

```ts
// packages/wallet-chains/src/types/asset.ts

export type AssetId = string;       // "sango", "eth", "btc", "sol"

export interface Asset {
  readonly id: AssetId;
  readonly symbol: string;
  readonly decimals: number;
  readonly kind: "native" | "token";
  readonly networkId: string;
}

export type AssetRef =
  | { readonly kind: "native"; readonly assetId: AssetId; readonly networkId: string }
  | { readonly kind: "token"; readonly networkId: string; readonly contract: string };
```

```ts
// packages/wallet-chains/src/types/token.ts

export interface Token {
  readonly networkId: string;
  readonly contract: string;
  readonly assetId: AssetId;
  readonly metadata: TokenMetadata;
}

export interface TokenMetadata {
  readonly name: string;
  readonly symbol: string;
  readonly decimals: number;
}
```

```ts
// packages/wallet-chains/src/types/balance.ts

export interface Balance {
  readonly assetId: AssetId;
  readonly networkId: string;
  readonly amount: bigint;
  readonly decimals: number;
}
```

```ts
// packages/wallet-chains/src/types/tx.ts

export interface UnsignedTransaction {
  readonly family: ChainFamily;
  readonly networkId: string;
  readonly payload: unknown;        // opaque — produit par le builder
  readonly meta: TxMeta;
}

export interface SignedTransaction {
  readonly unsigned: UnsignedTransaction;
  readonly raw: Uint8Array;
  readonly txHash: string;
}

export interface TxMeta {
  readonly from: string;
  readonly to: string;
  readonly assetRef: AssetRef;
  readonly amount: bigint;
}
```

```ts
// packages/wallet-chains/src/types/history.ts

export interface TxHistory {
  readonly total: number;
  readonly items: readonly HistoryItem[];
}

export interface HistoryItem {
  readonly txHash: string;
  readonly networkId: string;
  readonly status: "pending" | "confirmed" | "failed";
  readonly blockHeight?: number;
  readonly timestamp?: number;
  readonly from: string;
  readonly to: string;
  readonly assetRef: AssetRef;
  readonly amount: bigint;
}
```

### 3.3 `wallet-chains` — capacités

```ts
// packages/wallet-chains/src/capabilities/address-provider.ts

export interface AddressProvider {
  deriveAddress(account: AccountRef): Promise<string>;
  validateAddress(address: string): boolean;
}
```

```ts
// packages/wallet-chains/src/capabilities/balance-provider.ts

export interface BalanceProvider {
  getBalance(address: string, assetRef: AssetRef): Promise<Balance>;
}
```

```ts
// packages/wallet-chains/src/capabilities/history-provider.ts

export interface HistoryQuery {
  readonly address: string;
  readonly assetRef?: AssetRef;
  readonly limit: number;
  readonly offset?: number;
}

export interface HistoryProvider {
  getHistory(query: HistoryQuery): Promise<TxHistory>;
}
```

```ts
// packages/wallet-chains/src/capabilities/transaction-builder.ts

export interface SendParams {
  readonly from: string;
  readonly to: string;
  readonly assetRef: AssetRef;
  readonly amount: bigint;
  readonly memo?: Uint8Array;
}

export interface TransactionBuilder {
  build(params: SendParams): Promise<UnsignedTransaction>;
}
```

```ts
// packages/wallet-chains/src/capabilities/transaction-signer.ts

export interface TransactionSigner {
  sign(tx: UnsignedTransaction, signer: Signer): Promise<SignedTransaction>;
}
```

```ts
// packages/wallet-chains/src/capabilities/broadcaster.ts

export interface Broadcaster {
  broadcast(tx: SignedTransaction): Promise<string>;   // txHash
}
```

```ts
// packages/wallet-chains/src/capabilities/fee-estimator.ts

export interface FeeParams {
  readonly from: string;
  readonly to: string;
  readonly assetRef: AssetRef;
  readonly amount: bigint;
}

export interface FeeEstimate {
  readonly assetId: AssetId;
  readonly total: bigint;
  readonly breakdown?: Readonly<Record<string, bigint>>;
}

export interface FeeEstimator {
  estimate(params: FeeParams): Promise<FeeEstimate>;
}
```

```ts
// packages/wallet-chains/src/capabilities/token-provider.ts

export interface TokenProvider {
  listTokens(networkId: string): Promise<readonly Token[]>;
  getTokenBalance(address: string, token: Token): Promise<bigint>;
}
```

### 3.4 `wallet-chains` — ChainAdapter + Registry

```ts
// packages/wallet-chains/src/registry/chain-registry.ts

export interface ChainAdapter {
  readonly network: Network;

  // capacités obligatoires
  readonly addressProvider: AddressProvider;
  readonly balanceProvider: BalanceProvider;
  readonly historyProvider: HistoryProvider;

  // capacités optionnelles
  readonly transactionBuilder?: TransactionBuilder;
  readonly transactionSigner?: TransactionSigner;
  readonly broadcaster?: Broadcaster;
  readonly feeEstimator?: FeeEstimator;
  readonly tokenProvider?: TokenProvider;
}

export interface ChainRegistry {
  register(network: Network, factory: AdapterFactory): void;
  get(networkId: string): ChainAdapter | undefined;
  list(): readonly Network[];
  listByFamily(family: ChainFamily): readonly Network[];
}

export interface ProviderDeps {
  readonly rpcPool: RpcPool;
  readonly historyPool: HistoryProviderPool;
  readonly explorerRegistry: ExplorerRegistry;
}

export type AdapterFactory = (deps: ProviderDeps) => ChainAdapter;
```

### 3.5 `wallet-providers`

```ts
// packages/wallet-providers/src/rpc/rpc-pool.ts

export interface RpcPool {
  register(networkId: string, endpoints: readonly string[]): void;
  call<T = unknown>(networkId: string, method: string, params: unknown[]): Promise<T>;
}
```

```ts
// packages/wallet-providers/src/history/history-pool.ts

export interface HistoryProviderPool {
  register(networkId: string, provider: HistoryProvider): void;
  get(networkId: string): HistoryProvider | undefined;
}
```

```ts
// packages/wallet-providers/src/explorers/explorer-registry.ts

export interface ExplorerConfig {
  readonly baseUrl: string;
  readonly txPath: string;         // "/tx/{hash}"
  readonly addressPath: string;    // "/address/{addr}"
}

export interface ExplorerRegistry {
  register(networkId: string, config: ExplorerConfig): void;
  get(networkId: string): ExplorerConfig | undefined;
  linkToTx(networkId: string, txHash: string): string | undefined;
  linkToAddress(networkId: string, address: string): string | undefined;
}
```

### 3.6 `wallet-session`

```ts
// packages/wallet-session/src/session.ts

export interface AccountList {
  add(accountIndex: number): Promise<void>;
  remove(accountIndex: number): Promise<void>;
  list(): readonly AccountRef[];
  current(): AccountRef | undefined;
}

export interface AssetList {
  register(asset: Asset): void;
  get(assetId: AssetId, networkId: string): Asset | undefined;
  list(): readonly Asset[];
}

export interface WalletSession {
  readonly accounts: AccountList;
  readonly assets: AssetList;
  readonly chainRegistry: ChainRegistry;
  readonly signer: Signer;

  getBalance(account: AccountRef, assetRef: AssetRef): Promise<Balance>;

  getHistory(account: AccountRef, assetRef?: AssetRef, limit?: number): Promise<TxHistory>;

  estimateFee(params: FeeParams, account: AccountRef): Promise<FeeEstimate>;

  send(params: SendParams, account: AccountRef): Promise<string>;   // txHash

  explorerLink(account: AccountRef, txHash: string): string | undefined;
}
```

---

## 4. Flux d'exécution

### 4.1 Démarrage

```
App start
  │
  ▼
Créer RpcPool + HistoryProviderPool + ExplorerRegistry
  │
  ▼
Créer ChainRegistry
  │
  ├── register(SANGO_DEVNET, sangoAdapterFactory)
  │
  ▼
Créer Signer (mnemonic → WASM)
  │
  ▼
Créer WalletSession(chainRegistry, signer, accounts, assets)
```

### 4.2 Lecture de solde

```
UI: session.getBalance(account, assetRef)
  │
  ▼
WalletSession.resolveNetwork(assetRef) → networkId
  │
  ▼
chainRegistry.get(networkId) → adapter
  │
  ▼
adapter.balanceProvider.getBalance(address, assetRef)
  │
  ▼
network call (sango-sdk / rpc)
  │
  ▼
Balance
```

### 4.3 Envoi de transaction

```
UI: session.send(params, account)
  │
  ▼
resolveNetwork(params.assetRef) → adapter
  │
  ▼
adapter.addressProvider.deriveAddress(account) → from
  │
  ▼
adapter.feeEstimator.estimate(params)  (optionnel)
  │
  ▼
adapter.transactionBuilder.build(params + from) → unsigned
  │
  ▼
adapter.transactionSigner.sign(unsigned, signer) → signed
  │
  ▼
adapter.broadcaster.broadcast(signed) → txHash
  │
  ▼
UI: txHash + explorerLink
```

### 4.4 Historique

```
UI: session.getHistory(account, assetRef)
  │
  ▼
resolveNetwork(assetRef) → adapter
  │
  ▼
adapter.addressProvider.deriveAddress(account) → address
  │
  ▼
adapter.historyProvider.getHistory({address, limit, assetRef})
  │
  ▼
TxHistory
```

**Point clé** : aucun composant au-dessus de `ChainAdapter` ne sait
qu'il y a un `sango-sdk`, un `rpc-pool` ou une chaîne SANGO. C'est
l'adaptateur qui encapsule.

---

## 5. SANGO adapter (V0)

### 5.1 Config

```ts
// packages/wallet-chains/src/sango/config.ts

import type { Network } from "../types/network";

export const SANGO_CHAIN_ID_HEX =
  "0x1111111111111111111111111111111111111111111111111111111111111111";

export const SANGO_DEVNET: Network = {
  id: "sango-devnet",
  family: "sango",
  name: "Sango Devnet",
  chainId: SANGO_CHAIN_ID_HEX,
  nativeAsset: "sango",
  defaultRpcEndpoints: ["http://127.0.0.1:8545"],
  explorer: {
    baseUrl: "http://127.0.0.1:8090",
    txPath: "/tx/{hash}",
    addressPath: "/address/{addr}",
  },
};
```

### 5.2 Adapter

```ts
// packages/wallet-chains/src/sango/adapter.ts

import type { ChainAdapter, ProviderDeps } from "../registry/chain-registry";
import type { Network } from "../types/network";
import { SangoAddressProvider } from "./address-provider";
import { SangoBalanceProvider } from "./balance-provider";
import { SangoHistoryProvider } from "./history-provider";
import { SangoTransactionBuilder } from "./transaction-builder";
import { SangoTransactionSigner } from "./transaction-signer";
import { SangoBroadcaster } from "./broadcaster";
import { SangoFeeEstimator } from "./fee-estimator";

export function sangoAdapterFactory(
  network: Network,
  deps: ProviderDeps,
): ChainAdapter {
  return {
    network,
    addressProvider: new SangoAddressProvider(),
    balanceProvider: new SangoBalanceProvider(deps.rpcPool, network),
    historyProvider: new SangoHistoryProvider(deps.historyPool, network),
    transactionBuilder: new SangoTransactionBuilder(),
    transactionSigner: new SangoTransactionSigner(),
    broadcaster: new SangoBroadcaster(deps.rpcPool, network),
    feeEstimator: new SangoFeeEstimator(deps.rpcPool, network),
  };
}
```

**Note** : `SangoTokenProvider` n'existe pas en V0 (pas de tokens
natifs SANGO à part le natif).

### 5.3 AddressProvider

```ts
// packages/wallet-chains/src/sango/address-provider.ts

import type { AddressProvider } from "../capabilities/address-provider";
import type { AccountRef } from "wallet-core";
import { deriveSangoAddress } from "@sango/sango-sdk"; // existant
import { bech32mEncode } from "wallet-core";          // existant

export class SangoAddressProvider implements AddressProvider {
  async deriveAddress(account: AccountRef): Promise<string> {
    // Le signer fournit la clé publique ; ici on dérive l'adresse.
    // En pratique l'adapter reçoit la clé publique via le signer.
    // Voir infra — signature de `deriveAddress` étendue.
    throw new Error("implemented with signer in V0.1");
  }

  validateAddress(address: string): boolean {
    try {
      bech32mEncode.decode(address);
      return address.startsWith("tsango1") || address.startsWith("sango1");
    } catch {
      return false;
    }
  }
}
```

**Évolution à prévoir** : `AddressProvider::deriveAddress` a besoin
du `Signer` pour obtenir la clé publique. Deux options :
- Soit le `Signer` est passé au provider via le constructeur.
- Soit `deriveAddress` prend le `Signer` en paramètre.

**Choix V0** : le `Signer` est passé au provider via le constructeur.
Raison : garder la signature `deriveAddress(account)` simple, et
s'assurer qu'un provider de chaîne ne peut pas être instancié sans
signer.

---

## 6. Migration de l'existant SANGO

### 6.1 Étape 0 — Gel des tests

```
cargo test --workspace            (inchangé)
cd frontend && pnpm test           (inchangé)
```

Tous les tests doivent passer **avant** de toucher au code.

### 6.2 Étape 1 — Créer les paquets vides

Créer `wallet-chains`, `wallet-providers`, `wallet-session` avec
`package.json` minimal, sans dépendance sur l'existant.

**Aucun impact** sur le code existant.

### 6.3 Étape 2 — Types + interfaces

Remplir `wallet-chains/types/` et `wallet-chains/capabilities/` avec
**uniquement** les interfaces (pas d'implémentation).

**Aucun impact**.

### 6.4 Étape 3 — Provider RPC SANGO

Implémenter `wallet-providers/rpc/sango-rpc.ts` qui wrappe
`@sango/sango-rpc` (existant) derrière `RpcPool`.

Tests : mock du `sango-rpc` client, vérifier que `RpcPool.call`
transmet bien.

### 6.5 Étape 4 — SangoAdapter

Implémenter les 7 capacités SANGO :
- `SangoAddressProvider` — délègue à `sango-sdk` + `wallet-core`.
- `SangoBalanceProvider` — `sango_getAccount`.
- `SangoHistoryProvider` — `sango_getTransactionsByAddress`.
- `SangoTransactionBuilder` — construction tx native.
- `SangoTransactionSigner` — signe via `Signer`.
- `SangoBroadcaster` — `sango_sendTransaction`.
- `SangoFeeEstimator` — fixe (21 000 gas natif).

Tests : chaque capacité testée indépendamment, avec mock RPC.

### 6.6 Étape 5 — ChainRegistry

Implémenter `ChainRegistry` et enregistrer SANGO_DEVNET.

Tests : `registry.get("sango-devnet")` retourne un adapter complet.

### 6.7 Étape 6 — WalletSession

Implémenter `WalletSession` :
- `getBalance`, `getHistory`, `send`, `estimateFee`, `explorerLink`.
- Délègue tout à l'adapter via le registry.

Tests : mock adapter, vérifier que session délègue correctement.

### 6.8 Étape 7 — Migration UI

Migrer **une page à la fois** :

1. `/dashboard` — solde.
2. `/send` — envoi.
3. `/history` — liste.
4. `/history/:hash` — détail.
5. `/validators` — liste.
6. `/validators/:address` — détail.

Chaque page : remplacer les appels directs `sango-sdk` par
`walletSession.*`.

**Stratégie** : dual-path temporaire. La page appelle `walletSession`
si disponible, sinon fallback sur l'ancien code. Une fois les 6 pages
migrées, retirer le fallback.

### 6.9 Étape 8 — Suppression du code mort

Une fois les 6 pages migrées et les tests verts :
- Retirer les appels directs à `sango-sdk` dans les composants React.
- Retirer les hooks custom qui faisaient le pont.
- Conserver `sango-sdk` et `sango-rpc` (utilisés par les providers).

### 6.10 Étape 9 — Test de non-régression complet

```
pnpm test                              # 79 tests existants
pnpm build                             # doit produire un bundle
pnpm test:e2e                          # (si existant)
```

**Tous les tests doivent passer inchangés.**

---

## 7. Plan de tests

### 7.1 Tests unitaires par paquet

| Paquet | Tests |
|---|---|
| `wallet-core` | derivation (schemes, paths), signer (ed25519), storage |
| `wallet-chains` | types (constructeurs, validation), registry |
| `wallet-chains/sango` | 7 capacités, chacune avec mock RPC |
| `wallet-providers` | rpc-pool, history-pool, explorer-registry |
| `wallet-session` | délégation, résolution network, erreurs |
| `apps/wallet` | 79 tests existants (inchangés) |

### 7.2 Tests d'intégration

- **SANGO end-to-end** : créer wallet, dériver adresse, lire solde,
  construire tx, signer, broadcaster (mock RPC), vérifier txHash.
- **Session → Registry → Adapter** : vérifier que la résolution
  network fonctionne.
- **Explorer links** : vérifier que `explorerLink` génère la bonne URL.

### 7.3 Tests de non-régression SANGO

Critère : **les 79 tests frontend existants passent inchangés**, plus
les nouveaux tests.

**Aucune régression** sur :
- Format d'adresse bech32m.
- Sérialisation tx byte-à-byte.
- Signature Ed25519.
- Keyfile V3.

### 7.4 Test de gel

Une fois V0 mergé, un test `frozen-sango.spec.ts` vérifie que :
- L'adresse SANGO dérivée depuis une mnemonic fixe est identique à
  avant V0.
- La tx signée est identique byte-à-byte.
- La clé publique est identique.

Ce test sert de garde-fou pour toutes les futures refontes.

---

## 8. Rollback

Chaque étape est **additive** jusqu'à l'étape 7 (migration UI).

Si problème à l'étape N :
- Étapes 1-6 : supprimer le paquet créé, aucune trace dans le code
  existant.
- Étape 7 : revenir au commit précédent, la page revient à l'ancien
  code.
- Étape 8 : restaurer les appels directs.

**Aucun point de non-retour** avant l'étape 8.

---

## 9. Estimation

Pas d'estimation en semaines (D10). En **capacités livrées** :

| Étape | Livrable | Vérifiable |
|---|---|---|
| 0 | Tests verts avant toucher | `pnpm test` |
| 1 | Paquets vides créés | `pnpm build` |
| 2 | Interfaces typées | `pnpm tsc --noEmit` |
| 3 | RpcPool + adapter SANGO RPC | 1 test |
| 4 | 7 capacités SANGO | 7 tests |
| 5 | ChainRegistry + SANGO enregistré | 1 test |
| 6 | WalletSession | 5 tests |
| 7 | 6 pages migrées | 6 vérifs manuelles |
| 8 | Code mort supprimé | `pnpm build` |
| 9 | Non-régression complète | 79 + nouveaux tests |

**Chaque étape est indépendamment vérifiable.**

---

## 10. Décisions verrouillées pour V0

| # | Décision |
|---|---|
| V0-D1 | Pas de nouvelle chaîne dans V0 |
| V0-D2 | `Signer` passe au `AddressProvider` via constructeur |
| V0-D3 | `UnsignedTransaction.payload` est opaque (`unknown`) |
| V0-D4 | Dual-path temporaire pendant la migration UI |
| V0-D5 | `sango-sdk` et `sango-rpc` restent intacts |
| V0-D6 | `wallet-core` reste agnostique des chaînes |
| V0-D7 | Test de gel byte-à-byte obligatoire |

---

## 11. Ce que V0 ne fait pas

- ❌ Ajouter EVM, BTC, SOL.
- ❌ Ajouter des tokens.
- ❌ Ajouter des providers multiples (un seul endpoint SANGO).
- ❌ Ajouter un load-balancer RPC.
- ❌ Ajouter une UI de sélection réseau.
- ❌ Modifier le protocole SANGO.
- ❌ Toucher au backend Rust.

---

## 12. Critère de succès V0

V0 est considéré livré quand :

1. `wallet-chains`, `wallet-providers`, `wallet-session` existent
   avec leurs interfaces complètes.
2. `SangoAdapter` implémente les 7 capacités.
3. `ChainRegistry` contient SANGO_DEVNET.
4. `WalletSession` orchestre tout.
5. Les **6 pages principales** utilisent `WalletSession`.
6. Les **79 tests existants** passent inchangés.
7. Un test de gel byte-à-byte SANGO est ajouté.
8. Aucune ligne de code SANGO protocole n'a changé.

**Une fois V0 vert, on peut décider E0 / E1 / E2 / E3 / E4 sans
dette de design.**

---

## Annexe — Mapping ancien → nouveau

| Existant | Cible V0 |
|---|---|
| `wallet-core/keypair.ts` | `wallet-core/keys/keypair.ts` (inchangé) |
| `wallet-core/address.ts` (dérivation SANGO) | `wallet-chains/sango/address-provider.ts` |
| `wallet-core/address.ts` (bech32m) | `wallet-core/derivation/path.ts` + util |
| `wallet-core/signing.ts` | `wallet-core/signing/signer.ts` (interface) + `wallet-chains/sango/transaction-signer.ts` |
| `wallet-core/serialization.ts` | `wallet-core/` (inchangé, primitives) |
| `wallet-core/storage.ts` | `wallet-core/storage/` (inchangé) |
| `wallet-core/keyring.ts` | `wallet-core/keyring/` (inchangé) |
| `sango-sdk` (haut niveau) | `wallet-providers/` (wrappe) + `wallet-chains/sango/` |
| `sango-rpc` | `wallet-providers/rpc/sango-rpc.ts` |
| `apps/wallet` (appels directs) | `apps/wallet` via `WalletSession` |
```

---

## Note

Le fichier est prêt à être sauvegardé sous `docs/design/v0-architecture.md`.

**Ce document livre exactement ce que la revue a demandé** :

| Demande | Livré |
|---|---|
| Interfaces TS concrètes | §3 (10 interfaces) |
| Arborescence des fichiers | §2 |
| Flux `WalletSession → ChainRegistry → Adapter/Provider` | §4 |
| Plan de migration SANGO sans régression | §6 (9 étapes) |
| Tests de non-régression | §7 |
| Rollback | §8 |
| Critère de succès | §12 |
| Décisions V0 | §10 |

**Prochaines étapes possibles** :

1. **Valider les 7 décisions V0-D1 à V0-D7** (§10).
2. **Livrer l'implémentation** étape par étape (commencer par étape 1 + 2 : paquets vides + types).
3. **Ajouter** un test de gel SANGO avant toute migration UI.

Dis-moi :

- Tu valides le design doc tel quel ?
- Tu veux que je démarre l'implémentation par l'étape 1 + 2 (types + interfaces, sans impact) ?
- Ou tu veux d'abord relire les interfaces en détail et proposer des ajustements ?