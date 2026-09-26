# Sango — Spécification Bech32m des adresses natives

**Statut** : figé (V1)
**Source de vérité** : `sango-crypto::bech32m::tests::golden_vector_known_address`
**Référence croisée** : `frontend/packages/wallet-core/src/address.test.ts`

---

## 1. Périmètre

Représentation **utilisateur** d'une adresse native Sango. Ne concerne pas
le format consensus (20 bytes bruts) ni les adresses EVM (`0x…`).

---

## 2. Décisions normatives

| Aspect | Décision |
|---|---|
| Variante | **Bech32m** (BIP-350) |
| HRP mainnet | `sango` |
| HRP testnet | `tsango` |
| HRP devnet / local | `tsango` (identique à testnet) |
| Payload | 20 bytes bruts de `derive_native_address` |
| Préfixe / version / type | aucun |
| Domain separator | uniquement dans le hash de dérivation |

### 2.1 Justification des HRP

Devnet partage `tsango` avec testnet : un HRP dédié n'apporte aucun
bénéfice (le `chain_id` 32 bytes discrimine les réseaux au niveau
consensus) et crée de la confusion côté wallets.

### 2.2 Orthogonalité consensus / présentation

```text
derive_native_address(pk) → 20 bytes bruts   (CONSENSUS)
encode_native_address(a, network)            (PRÉSENTATION)

Bech32m ne doit jamais être appliqué dans du code consensus, ni hashé.
3. Procédure d'encodage
text

1. hrp      ← HRP(N)                          // "sango" ou "tsango"
2. payload  ← toWords(addr)                   // 20 bytes → 32 symboles 5-bit
3. checksum ← polymod_bech32m(hrp, payload)   // 6 symboles
4. output   ← hrp || "1" || payload || checksum

toWords = conversion 8→5 bits, MSB first, padding à droite.
20 bytes = 160 bits = 32 symboles 5-bit exactement → aucun padding.

Checksum Bech32m (constante 0x2bc830a3), pas Bech32 classique (0x1).
4. Procédure de décodage
text

1. (hrp, words) ← bech32m_decode(s)   // rejette si checksum invalide
2. addr         ← fromWords(words)     // 32 symboles → 20 bytes
3. assert len(addr) == 20
4. assert hrp == HRP(N)

Rejets obligatoires : chaîne vide, casse mixte, checksum invalide,
HRP inconnu, checksum Bech32 classique, payload ≠ 20 bytes.

Note d'implémentation sur les bibliothèques : deux familles :

    Décodeurs séparés (recommandé : @scure/base TS, crate bech32
    Rust) : bech32.decode ≠ bech32m.decode. Utiliser explicitement
    bech32m.decode, qui rejette naturellement Bech32 classique.

    Décodeurs à auto-détection (bitcoinjs-style) : decode unique →
    vérifier explicitement la constante Bech32m (0x2bc830a3).

Quelle que soit la famille, un re-encode + compare (avec normalisation
lowercase) est recommandé comme garde-fou anti-non-canonicalité. C'est la
stratégie du Rust (decode_checked_bech32m).
5. Golden vectors (normatifs)

Input :
text

PublicKey Ed25519  : c6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f73242
Adresse brute (hex): 02291e07839d715a4c78b8585449b7e367aa01ab

Outputs :
text

Mainnet : sango1qg53upurn4c45nrchpv9gjdhudn65qdtr5l9u6
Testnet : tsango1qg53upurn4c45nrchpv9gjdhudn65qdtv3xlde
Devnet  : tsango1qg53upurn4c45nrchpv9gjdhudn65qdtv3xlde

Emplacement des tests :

    Rust : sango-crypto::bech32m::tests::golden_vector_known_address

    TS : frontend/packages/wallet-core/src/address.test.ts

Synchronisation obligatoire — toute divergence = hard fork présentationnel.
6. Implémentations de référence
Langage	Fichier	Dépendance	Version
Rust	crates/sango-crypto/src/bech32m.rs	bech32	0.11
TypeScript	frontend/packages/wallet-core/src/address.ts	@scure/base	2.4.0 (pin exact dans packages/wallet-core/package.json)

Fonctions publiques correspondantes :
Opération	Rust	TypeScript
Encode	encode_native_address(addr, network)	encodeNativeAddress(bytes, network)
Decode (réseau connu)	decode_native_address(s, expected)	decodeNativeAddress(s, expected)
Decode (auto-détection)	try_decode_any_network(s)	(à rouvrir si besoin)
7. Cas ambigus (à éviter)
Chaîne (suffixe)	Raison
…k2cmcf	checksum Bech32m invalide — typo historique d'un test TS initial jamais généré par un encodeur. N'a jamais correspondu à un format Sango.
…kg0fec	Bech32 classique (BIP-173), pas Bech32m
…edkngm	idem (testnet)
8. Note "hard fork présentationnel"

Toute modification (variante, HRP, payload, toWords) casse les deux tests
(Rust + TS) → hard fork présentationnel. Pas un hard fork consensus
(aucun state_root affecté). Requiert : mise à jour coordonnée des deux
implémentations, note de migration utilisateur, nouvelle entrée dans ce
document.
9. Historique
Date	Auteur	Changement
2026-09-25	backend + frontend	Version initiale figée (V1)
2026-09-25	backend	§2.2, §6, §7 clarifiés ; §4 note auto-détection
2026-09-26	frontend	decodeNativeAddress TS (13/13 verts) ; @scure/base 2.4.0 pinné
2026-09-26	backend	§4 reformulée (familles décodeurs) ; §6 → 2.4.0
