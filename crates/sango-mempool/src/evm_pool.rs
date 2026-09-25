//! Mempool EVM — pool de transactions EVM en attente d'inclusion.
//!
//! ## Périmètre 4c.3.2
//!
//! **Préparation uniquement**. Ce mempool accepte, indexe, trie et évince
//! des `EvmTx`, mais **rien ne les inclut encore dans un bloc** : le
//! câblage `Driver → Block` arrive en 4c.3.3.
//!
//! ## Découplage strict
//!
//! Ce pool est **totalement séparé** du mempool natif (`crate::pool`).
//! Justification :
//!
//! - Espaces d'adresses différents : `NativeAddress` vs `EvmAddress`.
//! - Nonces indépendants : nonce natif (u64 Sango) vs nonce EVM (u64
//!   Ethereum).
//! - Politique de prix différente : `effective_price` (u128) pour le natif,
//!   `effective_priority_fee` (U256) pour l'EVM.
//! - Signature : Ed25519 pour le natif, secp256k1 pour l'EVM.
//!
//! Aucune transaction EVM ne peut être interprétée comme native (et
//! réciproquement) : le discriminant `Tx` (voir `sango-types::tx`) est
//! la seule passerelle entre les deux espaces.
//!
//! ## Recovery cryptographique du sender
//!
//! Le sender EVM est **dérivé de la signature**, jamais fourni par
//! l'appelant :
//!
//! ```text
//! signature secp256k1 (r, s, y_parity)
//!     ↓ signing_payload(tx)
//! Keccak256(payload) → message hash
//!     ↓ VerifyingKey::recover_from_prehash
//! uncompressed public key (65 bytes, 0x04 || X || Y)
//!     ↓ Keccak256(pubkey[1..])[12..]
//! EvmAddress
//! ```
//!
//! ## Tri par priorité effective
//!
//! La priorité effective **n'est pas figée à l'insertion** : elle dépend
//! du `base_fee` courant, qui peut évoluer bloc à bloc. On calcule donc
//! `effective_priority_fee(tx, base_fee)` au moment de la sélection.
//!
//! ```text
//! Legacy / EIP-2930 :  eff_priority = gas_price - base_fee
//! EIP-1559 / 7702   :  eff_priority = min(max_priority_fee,
//!                                        max_fee_per_gas - base_fee)
//! ```

use std::collections::{BTreeMap, HashMap};

use rlp::RlpStream;
use sango_crypto::keccak256;
use sango_primitives::{EvmAddress, Hash32, U256};
use sango_types::{EvmAccessList, EvmAuthorization, EvmTx};

use crate::error::EvmMempoolError;

/// Configuration du mempool EVM.
#[derive(Clone, Copy, Debug)]
pub struct EvmMempoolConfig {
    /// Capacité maximale en nombre de transactions.
    pub max_transactions: usize,
    /// Nombre maximum de transactions par sender.
    pub max_per_sender: usize,
    /// Fenêtre de nonces futurs acceptés (`current + max_nonce_gap`).
    pub max_nonce_gap: u64,
    /// Bump de remplacement en basis points (`1_000` = +10 %).
    pub replacement_bump_bps: u32,
}

impl Default for EvmMempoolConfig {
    fn default() -> Self {
        Self {
            max_transactions: 100_000,
            max_per_sender: 64,
            max_nonce_gap: 64,
            replacement_bump_bps: 1_000,
        }
    }
}

/// Entrée du mempool EVM.
///
/// **Pas de champ `effective_priority_fee`** : cette valeur dépend du
/// `base_fee` courant, qui varie à chaque bloc. On la calcule à la
/// sélection via [`effective_priority_fee`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvmMempoolEntry {
    /// Transaction EVM.
    pub tx: EvmTx,
    /// Hash canonique de la transaction (Ethereum : `Keccak256(typed)`).
    pub tx_hash: Hash32,
    /// Adresse EVM de l'émetteur, **récupérée cryptographiquement** de la
    /// signature secp256k1.
    pub sender: EvmAddress,
    /// Ordre d'arrivée (timestamp logique interne).
    pub arrival: u64,
}

/// Mempool EVM.
#[derive(Debug)]
pub struct EvmMempool {
    config: EvmMempoolConfig,
    /// Entrées par hash.
    by_hash: HashMap<Hash32, EvmMempoolEntry>,
    /// Index secondaire : `(sender, nonce) → hash`.
    by_sender_nonce: BTreeMap<(EvmAddress, u64), Hash32>,
    /// Ordre d'arrivée, monotone.
    arrival_counter: u64,
    /// Nombre de transactions par sender.
    per_sender_count: HashMap<EvmAddress, u32>,
}

impl EvmMempool {
    /// Crée un mempool EVM avec la configuration donnée.
    #[must_use]
    pub fn new(config: EvmMempoolConfig) -> Self {
        Self {
            config,
            by_hash: HashMap::new(),
            by_sender_nonce: BTreeMap::new(),
            arrival_counter: 0,
            per_sender_count: HashMap::new(),
        }
    }

    /// Nombre de transactions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_hash.len()
    }

    /// Vrai si le mempool est vide.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }

    /// Configuration.
    #[must_use]
    pub fn config(&self) -> &EvmMempoolConfig {
        &self.config
    }

    /// Vrai si le hash est présent.
    #[must_use]
    pub fn contains(&self, hash: &Hash32) -> bool {
        self.by_hash.contains_key(hash)
    }

    /// Lit une entrée par hash.
    #[must_use]
    pub fn get(&self, hash: &Hash32) -> Option<&EvmMempoolEntry> {
        self.by_hash.get(hash)
    }

    /// Admet une transaction EVM.
    ///
    /// ## Contrat
    ///
    /// - Le sender est **récupéré cryptographiquement** de la signature
    ///   (voir [`recover_sender`]). Toute signature invalide est rejetée
    ///   avec [`EvmMempoolError::InvalidSignature`].
    /// - Doublon de hash → [`EvmMempoolError::Duplicate`].
    /// - Capacité globale ou par sender atteinte → [`EvmMempoolError::Full`].
    /// - `max_fee_per_gas < base_fee` → [`EvmMempoolError::MaxFeeBelowBaseFee`].
    /// - Nonce déjà occupé par une autre tx :
    ///   - si la nouvelle offre un bump `>= replacement_bump_bps` **sur la
    ///     priorité effective courante**, elle remplace l'ancienne ;
    ///   - sinon → [`EvmMempoolError::ReplacementFeeTooLow`].
    pub fn add(
        &mut self,
        tx: EvmTx,
        base_fee: U256,
        sender_nonce: u64,
    ) -> Result<Hash32, EvmMempoolError> {
        let tx_hash = tx_hash(&tx);

        if self.by_hash.contains_key(&tx_hash) {
            return Err(EvmMempoolError::Duplicate(tx_hash));
        }

        // (1) Vérifier que la tx offre au moins la base fee courante.
        //     Legacy/EIP-2930 utilisent `gas_price` comme max implicite.
        let max_fee_per_gas = max_fee_per_gas(&tx);
        if max_fee_per_gas < base_fee {
            return Err(EvmMempoolError::MaxFeeBelowBaseFee {
                max_fee: max_fee_per_gas,
                base_fee,
            });
        }

        // (2) Récupérer le sender cryptographiquement.
        let sender = recover_sender(&tx)?;

        // (3) Fenêtre de nonce.
        let nonce = tx.nonce();
        let min_nonce = sender_nonce;
        let max_nonce = sender_nonce.saturating_add(self.config.max_nonce_gap);
        if nonce < min_nonce {
            return Err(EvmMempoolError::NonceTooLow {
                expected: min_nonce,
                got: nonce,
            });
        }
        if nonce > max_nonce {
            return Err(EvmMempoolError::NonceTooHigh {
                expected: max_nonce,
                got: nonce,
            });
        }

        // (4) Collision de nonce pour ce sender ?
        let key = (sender, nonce);
        if let Some(existing_hash) = self.by_sender_nonce.get(&key).copied() {
            let existing = self.by_hash.get(&existing_hash).expect("index consistant");
            let new_priority = effective_priority_fee(&tx, base_fee);
            let old_priority = effective_priority_fee(&existing.tx, base_fee);
            let bump_bps = self.config.replacement_bump_bps as u128;
            // min_required = old * (10_000 + bump) / 10_000
            let min_required = old_priority
                .saturating_mul(U256::from(10_000u64 + bump_bps as u64))
                .checked_div(U256::from(10_000u64))
                .unwrap_or(old_priority);
            if new_priority < min_required {
                return Err(EvmMempoolError::ReplacementFeeTooLow {
                    needed: min_required,
                    got: new_priority,
                });
            }
            // Remplacer : retirer l'ancienne.
            self.remove(&existing_hash);
        }

        // (5) Capacité globale.
        if self.by_hash.len() >= self.config.max_transactions {
            return Err(EvmMempoolError::Full);
        }

        // (6) Capacité par sender.
        let count = self.per_sender_count.entry(sender).or_insert(0);
        if *count >= self.config.max_per_sender as u32 {
            return Err(EvmMempoolError::Full);
        }
        *count += 1;

        self.arrival_counter = self.arrival_counter.saturating_add(1);
        let entry = EvmMempoolEntry {
            tx,
            tx_hash,
            sender,
            arrival: self.arrival_counter,
        };
        self.by_hash.insert(tx_hash, entry);
        self.by_sender_nonce.insert(key, tx_hash);
        Ok(tx_hash)
    }

    /// Retire une transaction par hash.
    pub fn remove(&mut self, hash: &Hash32) -> Option<EvmMempoolEntry> {
        let entry = self.by_hash.remove(hash)?;
        self.by_sender_nonce
            .remove(&(entry.sender, entry.tx.nonce()));
        if let Some(count) = self.per_sender_count.get_mut(&entry.sender) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.per_sender_count.remove(&entry.sender);
            }
        }
        Some(entry)
    }

    /// Sélectionne jusqu'à `max_count` transactions pour un bloc.
    ///
    /// ## Tri
    ///
    /// 1. `effective_priority_fee(tx, base_fee)` décroissant.
    /// 2. `arrival` croissant (FIFO à prix égal).
    ///
    /// ## Dépendances de nonce
    ///
    /// Pour un même sender, on ne peut inclure un nonce `n` sans avoir
    /// inclus `n-1` (dans la même sélection ou déjà appliqué on-chain).
    ///
    /// Le `base_fee` est **fourni par l'appelant** : on ne fige donc
    /// jamais une priorité obsolète.
    #[must_use]
    pub fn select_for_block(
        &self,
        max_count: usize,
        base_nonces: &HashMap<EvmAddress, u64>,
        base_fee: U256,
    ) -> Vec<EvmMempoolEntry> {
        let mut candidates: Vec<&EvmMempoolEntry> = self.by_hash.values().collect();
        candidates.sort_by(|a, b| {
            let pa = effective_priority_fee(&a.tx, base_fee);
            let pb = effective_priority_fee(&b.tx, base_fee);
            pb.cmp(&pa).then(a.arrival.cmp(&b.arrival))
        });

        let mut selected = Vec::new();
        let mut next_nonce: HashMap<EvmAddress, u64> = base_nonces.clone();

        for entry in candidates {
            if selected.len() >= max_count {
                break;
            }
            let expected = next_nonce.get(&entry.sender).copied().unwrap_or(0);
            let nonce = entry.tx.nonce();
            if nonce == expected {
                next_nonce.insert(entry.sender, expected + 1);
                selected.push(entry.clone());
            } else if nonce < expected {
                continue;
            }
            // nonce > expected : on saute (dépendance manquante).
        }
        selected
    }

    /// Retire toutes les transactions dont le nonce est strictement
    /// inférieur à `min_nonces[sender]`.
    pub fn prune_below_nonces(&mut self, min_nonces: &HashMap<EvmAddress, u64>) -> usize {
        let mut to_remove = Vec::new();
        for (key, hash) in &self.by_sender_nonce {
            if let Some(&min) = min_nonces.get(&key.0) {
                if key.1 < min {
                    to_remove.push(*hash);
                }
            }
        }
        let count = to_remove.len();
        for hash in to_remove {
            self.remove(&hash);
        }
        count
    }

    /// Retire toutes les transactions (ex. reset).
    pub fn clear(&mut self) {
        self.by_hash.clear();
        self.by_sender_nonce.clear();
        self.per_sender_count.clear();
    }

    /// Retire les transactions dont `max_fee_per_gas < new_base_fee`.
    pub fn evict_below_base_fee(&mut self, new_base_fee: U256) -> usize {
        let to_remove: Vec<Hash32> = self
            .by_hash
            .values()
            .filter(|e| max_fee_per_gas(&e.tx) < new_base_fee)
            .map(|e| e.tx_hash)
            .collect();
        let count = to_remove.len();
        for hash in to_remove {
            self.remove(&hash);
        }
        count
    }

    /// Hashes connus.
    #[must_use]
    pub fn hashes(&self) -> std::collections::HashSet<Hash32> {
        self.by_hash.keys().copied().collect()
    }

    /// Hashes de toutes les transactions, triés par ordre de sélection
    /// avec un `base_fee` donné.
    #[must_use]
    pub fn ordered_hashes(&self, base_fee: U256) -> Vec<Hash32> {
        let mut candidates: Vec<&EvmMempoolEntry> = self.by_hash.values().collect();
        candidates.sort_by(|a, b| {
            let pa = effective_priority_fee(&a.tx, base_fee);
            let pb = effective_priority_fee(&b.tx, base_fee);
            pb.cmp(&pa).then(a.arrival.cmp(&b.arrival))
        });
        candidates.into_iter().map(|e| e.tx_hash).collect()
    }
}

impl Default for EvmMempool {
    fn default() -> Self {
        Self::new(EvmMempoolConfig::default())
    }
}

// --- Priors ----------------------------------------------------------------

/// `max_fee_per_gas` **brut** d'une tx (avant éventuelle saturation par
/// la base fee courante).
///
/// - Legacy / EIP-2930 : `gas_price`.
/// - EIP-1559 / 7702 : `max_fee_per_gas`.
#[must_use]
pub fn max_fee_per_gas(tx: &EvmTx) -> U256 {
    match tx {
        EvmTx::Legacy { gas_price, .. } | EvmTx::Eip2930 { gas_price, .. } => *gas_price,
        EvmTx::Eip1559 {
            max_fee_per_gas, ..
        }
        | EvmTx::Eip7702 {
            max_fee_per_gas, ..
        } => *max_fee_per_gas,
    }
}

/// `max_priority_fee_per_gas` **brut** d'une tx.
///
/// - Legacy / EIP-2930 : pas de priority fee distincte ; on assimile
///   `gas_price` à un tip maximal implicite.
/// - EIP-1559 / 7702 : `max_priority_fee_per_gas`.
#[must_use]
pub fn max_priority_fee(tx: &EvmTx) -> U256 {
    match tx {
        EvmTx::Legacy { gas_price, .. } | EvmTx::Eip2930 { gas_price, .. } => *gas_price,
        EvmTx::Eip1559 {
            max_priority_fee_per_gas,
            ..
        }
        | EvmTx::Eip7702 {
            max_priority_fee_per_gas,
            ..
        } => *max_priority_fee_per_gas,
    }
}

/// Priorité effective d'une tx pour un `base_fee` donné.
///
/// ## Formule
///
/// ```text
/// effective_gas_price    = min(max_fee, base_fee + max_priority_fee)
/// effective_priority_fee = effective_gas_price - base_fee
///                        = min(max_priority_fee,
///                              max_fee - base_fee)
/// ```
///
/// Si `max_fee < base_fee`, le second terme sature à 0 (la tx ne sera
/// pas sélectionnable, mais le calcul ne panique pas).
///
/// ## Non figée
///
/// Cette valeur **dépend du `base_fee` courant** : elle doit être
/// recalculée à chaque sélection. Voir [`EvmMempool::select_for_block`].
#[must_use]
pub fn effective_priority_fee(tx: &EvmTx, base_fee: U256) -> U256 {
    let max_fee = max_fee_per_gas(tx);
    let max_priority = max_priority_fee(tx);
    let budget = max_fee.saturating_sub(base_fee);
    max_priority.min(budget)
}

/// Hash canonique d'une tx EVM : `Keccak256(typed_tx_bytes)`.
#[must_use]
pub fn tx_hash(tx: &EvmTx) -> Hash32 {
    keccak256(&tx.encode_ethereum_typed())
}

// --- Recovery du sender ----------------------------------------------------

/// Récupère l'adresse EVM de l'émetteur d'une tx depuis sa signature
/// secp256k1.
///
/// ## Règle normative
///
/// ```text
/// signing_payload(tx)  →  message
/// Keccak256(message)   →  prehash (32 bytes)
/// secp256k1 recovery (r, s, y_parity)
///     →  uncompressed public key (65 bytes : 0x04 || X || Y)
/// Keccak256(pubkey[1..])[12..]
///     →  EvmAddress
/// ```
///
/// ## Sécurité
///
/// Le mempool ne doit **jamais** faire confiance à un sender fourni par
/// l'appelant (`eth_sendRawTransaction`). Le sender est toujours dérivé
/// de la signature, ce qui empêche toute usurpation.
pub fn recover_sender(tx: &EvmTx) -> Result<EvmAddress, EvmMempoolError> {
    let payload = signing_payload(tx);
    let prehash = keccak256(&payload);

    let (r, s, y_parity) = match tx {
        EvmTx::Legacy { r, s, y_parity, .. }
        | EvmTx::Eip2930 { r, s, y_parity, .. }
        | EvmTx::Eip1559 { r, s, y_parity, .. }
        | EvmTx::Eip7702 { r, s, y_parity, .. } => (*r, *s, *y_parity),
    };

    if y_parity > 1 {
        return Err(EvmMempoolError::InvalidSignature);
    }

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&r.to_be_bytes::<32>());
    sig_bytes[32..].copy_from_slice(&s.to_be_bytes::<32>());

    let signature = k256::ecdsa::Signature::from_slice(&sig_bytes)
        .map_err(|_| EvmMempoolError::InvalidSignature)?;

    let recovery_id = k256::ecdsa::RecoveryId::try_from(y_parity)
        .map_err(|_| EvmMempoolError::InvalidSignature)?;

    let verifying_key = k256::ecdsa::VerifyingKey::recover_from_prehash(
        prehash.as_bytes(),
        &signature,
        recovery_id,
    )
    .map_err(|_| EvmMempoolError::InvalidSignature)?;

    let point = verifying_key.to_encoded_point(false);
    let encoded = point.as_bytes();
    if encoded.len() != 65 || encoded[0] != 0x04 {
        return Err(EvmMempoolError::InvalidSignature);
    }
    let addr_hash = keccak256(&encoded[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&addr_hash.as_bytes()[12..]);
    Ok(EvmAddress::from_bytes(addr))
}

// --- Signing payload -------------------------------------------------------

/// Reconstruit les **bytes signés** d'une tx EVM (sans `v`, `r`, `s`).
///
/// - Legacy EIP-155 : `RLP([nonce, gas_price, gas_limit, to, value, data,
///   chain_id, 0, 0])` (sans préfixe 0x00).
/// - EIP-2930 : `0x01 || RLP([chain_id, nonce, gas_price, gas_limit, to,
///   value, data, access_list])`.
/// - EIP-1559 : `0x02 || RLP([chain_id, nonce, max_priority_fee,
///   max_fee, gas_limit, to, value, data, access_list])`.
/// - EIP-7702 : `0x04 || RLP([chain_id, nonce, max_priority_fee,
///   max_fee, gas_limit, to, value, data, access_list,
///   authorization_list])`.
fn signing_payload(tx: &EvmTx) -> Vec<u8> {
    match tx {
        EvmTx::Legacy {
            chain_id,
            nonce,
            gas_price,
            gas_limit,
            to,
            value,
            data,
            ..
        } => {
            let mut s = RlpStream::new_list(9);
            enc_u64(&mut s, *nonce);
            enc_u256(&mut s, *gas_price);
            enc_u64(&mut s, *gas_limit);
            enc_to(&mut s, *to);
            enc_u256(&mut s, *value);
            s.append(&data.as_slice());
            enc_u64(&mut s, *chain_id);
            s.append_empty_data();
            s.append_empty_data();
            s.out().to_vec()
        }
        EvmTx::Eip2930 {
            chain_id,
            nonce,
            gas_price,
            gas_limit,
            to,
            value,
            data,
            access_list,
            ..
        } => {
            let mut s = RlpStream::new_list(11);
            enc_u64(&mut s, *chain_id);
            enc_u64(&mut s, *nonce);
            enc_u256(&mut s, *gas_price);
            enc_u64(&mut s, *gas_limit);
            enc_to(&mut s, *to);
            enc_u256(&mut s, *value);
            s.append(&data.as_slice());
            enc_access_list(&mut s, access_list);
            // Pas de y_parity / r / s
            let mut out = vec![0x01u8];
            out.extend_from_slice(&s.out());
            out
        }
        EvmTx::Eip1559 {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            value,
            data,
            access_list,
            ..
        } => {
            let mut s = RlpStream::new_list(12);
            enc_u64(&mut s, *chain_id);
            enc_u64(&mut s, *nonce);
            enc_u256(&mut s, *max_priority_fee_per_gas);
            enc_u256(&mut s, *max_fee_per_gas);
            enc_u64(&mut s, *gas_limit);
            enc_to(&mut s, *to);
            enc_u256(&mut s, *value);
            s.append(&data.as_slice());
            enc_access_list(&mut s, access_list);
            let mut out = vec![0x02u8];
            out.extend_from_slice(&s.out());
            out
        }
        EvmTx::Eip7702 {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            value,
            data,
            access_list,
            authorization_list,
            ..
        } => {
            let mut s = RlpStream::new_list(13);
            enc_u64(&mut s, *chain_id);
            enc_u64(&mut s, *nonce);
            enc_u256(&mut s, *max_priority_fee_per_gas);
            enc_u256(&mut s, *max_fee_per_gas);
            enc_u64(&mut s, *gas_limit);
            let to_bytes: &[u8] = to.as_bytes();
            s.append(&to_bytes);
            enc_u256(&mut s, *value);
            s.append(&data.as_slice());
            enc_access_list(&mut s, access_list);
            enc_authorization_list(&mut s, authorization_list);
            let mut out = vec![0x04u8];
            out.extend_from_slice(&s.out());
            out
        }
    }
}

// --- Helpers RLP (privés) --------------------------------------------------

fn enc_u64(s: &mut RlpStream, v: u64) {
    let bytes = v.to_be_bytes();
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(8);
    let slice: &[u8] = &bytes[start..];
    s.append(&slice);
}

fn enc_u256(s: &mut RlpStream, v: U256) {
    let bytes = v.to_be_bytes::<32>();
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(32);
    let slice: &[u8] = &bytes[start..];
    s.append(&slice);
}

fn enc_to(s: &mut RlpStream, to: Option<EvmAddress>) {
    match to {
        Some(a) => {
            let bytes: &[u8] = a.as_bytes();
            s.append(&bytes);
        }
        None => {
            s.append_empty_data();
        }
    }
}

fn enc_access_list(s: &mut RlpStream, list: &EvmAccessList) {
    s.begin_list(list.len());
    for item in list {
        s.begin_list(2);
        let addr_bytes: &[u8] = item.address.as_bytes();
        s.append(&addr_bytes);
        s.begin_list(item.storage_keys.len());
        for key in &item.storage_keys {
            let key_bytes: &[u8] = key.as_bytes();
            s.append(&key_bytes);
        }
    }
}

fn enc_authorization_list(s: &mut RlpStream, list: &[EvmAuthorization]) {
    s.begin_list(list.len());
    for auth in list {
        s.begin_list(6);
        enc_u256(s, auth.chain_id);
        let addr_bytes: &[u8] = auth.address.as_bytes();
        s.append(&addr_bytes);
        enc_u64(s, auth.nonce);
        enc_u64(s, auth.y_parity as u64);
        enc_u256(s, auth.r);
        enc_u256(s, auth.s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> EvmAddress {
        EvmAddress::from_bytes([b; 20])
    }

    fn u(v: u64) -> U256 {
        U256::from(v)
    }

    /// Signe un `Legacy` tx avec la clé donnée et renvoie `(r, s, y_parity)`.
    fn sign_legacy(sk: &k256::ecdsa::SigningKey, tx_unsigned: &EvmTx) -> (U256, U256, u8) {
        let payload = signing_payload(tx_unsigned);
        let prehash = keccak256(&payload);
        let (sig, recid) = sk
            .sign_prehash_recoverable(prehash.as_bytes())
            .expect("sign");
        let sig_bytes = sig.to_bytes();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig_bytes[..32]);
        s.copy_from_slice(&sig_bytes[32..]);
        (
            U256::from_be_bytes::<32>(r),
            U256::from_be_bytes::<32>(s),
            recid.to_byte(),
        )
    }

    fn signing_key(seed: [u8; 32]) -> k256::ecdsa::SigningKey {
        k256::ecdsa::SigningKey::from_bytes((&seed).into()).expect("valid scalar")
    }

    /// Construit une Legacy tx signée et retourne `(tx, expected_addr)`.
    fn signed_legacy(
        sk: &k256::ecdsa::SigningKey,
        nonce: u64,
        gas_price: u64,
    ) -> (EvmTx, EvmAddress) {
        let unsigned = EvmTx::Legacy {
            chain_id: 7777,
            nonce,
            gas_price: u(gas_price),
            gas_limit: 21_000,
            to: Some(addr(0xbb)),
            value: u(100),
            data: vec![],
            y_parity: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };
        let (r, s, y_parity) = sign_legacy(sk, &unsigned);
        let tx = match unsigned {
            EvmTx::Legacy {
                chain_id,
                nonce,
                gas_price,
                gas_limit,
                to,
                value,
                data,
                ..
            } => EvmTx::Legacy {
                chain_id,
                nonce,
                gas_price,
                gas_limit,
                to,
                value,
                data,
                y_parity,
                r,
                s,
            },
            _ => unreachable!(),
        };
        let vk = sk.verifying_key();
        let point = vk.to_encoded_point(false);
        let h = keccak256(&point.as_bytes()[1..]);
        let mut a = [0u8; 20];
        a.copy_from_slice(&h.as_bytes()[12..]);
        (tx, EvmAddress::from_bytes(a))
    }

    // --- Recovery ----------------------------------------------------------

    #[test]
    fn recover_sender_legacy_roundtrip() {
        let sk = signing_key([0x42u8; 32]);
        let (tx, expected) = signed_legacy(&sk, 0, 1_000_000_000);
        let got = recover_sender(&tx).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn recover_sender_rejects_bad_y_parity() {
        let sk = signing_key([0x42u8; 32]);
        let (tx, _) = signed_legacy(&sk, 0, 1_000_000_000);
        let bad = match tx {
            EvmTx::Legacy {
                chain_id,
                nonce,
                gas_price,
                gas_limit,
                to,
                value,
                data,
                r,
                s,
                ..
            } => EvmTx::Legacy {
                chain_id,
                nonce,
                gas_price,
                gas_limit,
                to,
                value,
                data,
                y_parity: 2,
                r,
                s,
            },
            _ => unreachable!(),
        };
        assert_eq!(
            recover_sender(&bad).unwrap_err(),
            EvmMempoolError::InvalidSignature
        );
    }

    #[test]
    fn recover_sender_rejects_zero_signature() {
        let tx = EvmTx::Legacy {
            chain_id: 7777,
            nonce: 0,
            gas_price: u(1),
            gas_limit: 21_000,
            to: Some(addr(0xbb)),
            value: u(0),
            data: vec![],
            y_parity: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };
        assert!(matches!(
            recover_sender(&tx),
            Err(EvmMempoolError::InvalidSignature)
        ));
    }

    // --- tx_hash -----------------------------------------------------------

    #[test]
    fn tx_hash_is_keccak_of_typed() {
        let sk = signing_key([0x42u8; 32]);
        let (tx, _) = signed_legacy(&sk, 0, 1);
        assert_eq!(tx_hash(&tx), keccak256(&tx.encode_ethereum_typed()));
    }

    // --- effective_priority_fee --------------------------------------------

    #[test]
    fn priority_legacy_is_gas_price_minus_base() {
        let tx = EvmTx::Legacy {
            chain_id: 1,
            nonce: 0,
            gas_price: u(100),
            gas_limit: 21_000,
            to: Some(addr(0xaa)),
            value: u(0),
            data: vec![],
            y_parity: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };
        assert_eq!(effective_priority_fee(&tx, u(30)), u(70));
    }

    #[test]
    fn priority_legacy_saturates_below_base() {
        let tx = EvmTx::Legacy {
            chain_id: 1,
            nonce: 0,
            gas_price: u(10),
            gas_limit: 21_000,
            to: Some(addr(0xaa)),
            value: u(0),
            data: vec![],
            y_parity: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };
        assert_eq!(effective_priority_fee(&tx, u(100)), U256::ZERO);
    }

    #[test]
    fn priority_1559_capped_by_priority() {
        let tx = EvmTx::Eip1559 {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: u(5),
            max_fee_per_gas: u(100),
            gas_limit: 21_000,
            to: Some(addr(0xaa)),
            value: u(0),
            data: vec![],
            access_list: vec![],
            y_parity: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };
        assert_eq!(effective_priority_fee(&tx, u(30)), u(5));
    }

    #[test]
    fn priority_1559_capped_by_budget() {
        let tx = EvmTx::Eip1559 {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: u(50),
            max_fee_per_gas: u(100),
            gas_limit: 21_000,
            to: Some(addr(0xaa)),
            value: u(0),
            data: vec![],
            access_list: vec![],
            y_parity: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };
        // budget = 100 - 80 = 20 ; priority = 50 ; eff = min(50, 20) = 20
        assert_eq!(effective_priority_fee(&tx, u(80)), u(20));
    }

    // --- add / remove ------------------------------------------------------

    #[test]
    fn add_and_remove() {
        let sk = signing_key([0x42u8; 32]);
        let (tx, addr_expected) = signed_legacy(&sk, 0, 100);
        let h = tx_hash(&tx);
        let mut pool = EvmMempool::default();
        let inserted = pool.add(tx, u(10), 0).unwrap();
        assert_eq!(inserted, h);
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&h));
        assert_eq!(pool.get(&h).unwrap().sender, addr_expected);
        pool.remove(&h);
        assert!(pool.is_empty());
    }

    #[test]
    fn duplicate_rejected() {
        let sk = signing_key([0x42u8; 32]);
        let (tx, _) = signed_legacy(&sk, 0, 100);
        let mut pool = EvmMempool::default();
        pool.add(tx.clone(), u(10), 0).unwrap();
        assert!(matches!(
            pool.add(tx, u(10), 0),
            Err(EvmMempoolError::Duplicate(_))
        ));
    }

    #[test]
    fn max_fee_below_base_rejected() {
        let sk = signing_key([0x42u8; 32]);
        let (tx, _) = signed_legacy(&sk, 0, 5);
        let mut pool = EvmMempool::default();
        assert!(matches!(
            pool.add(tx, u(100), 0),
            Err(EvmMempoolError::MaxFeeBelowBaseFee { .. })
        ));
    }

    #[test]
    fn nonce_too_low_rejected() {
        let sk = signing_key([0x42u8; 32]);
        let (tx, _) = signed_legacy(&sk, 3, 100);
        let mut pool = EvmMempool::default();
        assert!(matches!(
            pool.add(tx, u(10), 5),
            Err(EvmMempoolError::NonceTooLow { .. })
        ));
    }

    #[test]
    fn nonce_too_high_rejected() {
        let sk = signing_key([0x42u8; 32]);
        let (tx, _) = signed_legacy(&sk, 200, 100);
        let mut pool = EvmMempool::default();
        assert!(matches!(
            pool.add(tx, u(10), 0),
            Err(EvmMempoolError::NonceTooHigh { .. })
        ));
    }

    #[test]
    fn replacement_requires_bump() {
        let sk = signing_key([0x42u8; 32]);
        let (tx1, _) = signed_legacy(&sk, 0, 100);
        let (tx2, _) = signed_legacy(&sk, 0, 105); // +5 % seulement
        let mut pool = EvmMempool::default();
        pool.add(tx1, u(10), 0).unwrap();
        assert!(matches!(
            pool.add(tx2, u(10), 0),
            Err(EvmMempoolError::ReplacementFeeTooLow { .. })
        ));
    }

    #[test]
    fn replacement_with_sufficient_bump_accepted() {
        let sk = signing_key([0x42u8; 32]);
        let (tx1, _) = signed_legacy(&sk, 0, 100);
        let (tx2, _) = signed_legacy(&sk, 0, 200); // +100 %
        let mut pool = EvmMempool::default();
        let h1 = pool.add(tx1, u(10), 0).unwrap();
        let h2 = pool.add(tx2, u(10), 0).unwrap();
        assert_ne!(h1, h2);
        assert_eq!(pool.len(), 1);
        assert!(!pool.contains(&h1));
        assert!(pool.contains(&h2));
    }

    #[test]
    fn per_sender_capacity() {
        let sk = signing_key([0x42u8; 32]);
        let cfg = EvmMempoolConfig {
            max_per_sender: 2,
            ..Default::default()
        };
        let mut pool = EvmMempool::new(cfg);
        let (tx0, _) = signed_legacy(&sk, 0, 100);
        let (tx1, _) = signed_legacy(&sk, 1, 100);
        let (tx2, _) = signed_legacy(&sk, 2, 100);
        pool.add(tx0, u(0), 0).unwrap();
        pool.add(tx1, u(0), 0).unwrap();
        assert!(matches!(pool.add(tx2, u(0), 0), Err(EvmMempoolError::Full)));
    }

    #[test]
    fn global_capacity() {
        let sk1 = signing_key([0x01u8; 32]);
        let sk2 = signing_key([0x02u8; 32]);
        let sk3 = signing_key([0x03u8; 32]);
        let cfg = EvmMempoolConfig {
            max_transactions: 2,
            ..Default::default()
        };
        let mut pool = EvmMempool::new(cfg);
        let (t1, _) = signed_legacy(&sk1, 0, 100);
        let (t2, _) = signed_legacy(&sk2, 0, 100);
        let (t3, _) = signed_legacy(&sk3, 0, 100);
        pool.add(t1, u(0), 0).unwrap();
        pool.add(t2, u(0), 0).unwrap();
        assert!(matches!(pool.add(t3, u(0), 0), Err(EvmMempoolError::Full)));
    }

    // --- select_for_block --------------------------------------------------

    #[test]
    fn select_orders_by_priority_then_arrival() {
        let sk1 = signing_key([0x01u8; 32]);
        let sk2 = signing_key([0x02u8; 32]);
        let sk3 = signing_key([0x03u8; 32]);
        let mut pool = EvmMempool::default();

        // Arrivée : t1 (gas_price 20, eff=10), t2 (gas_price 30, eff=20), t3 (gas_price 30, eff=20).
        let (t1, _) = signed_legacy(&sk1, 0, 20);
        let (t2, _) = signed_legacy(&sk2, 0, 30);
        let (t3, _) = signed_legacy(&sk3, 0, 30);
        pool.add(t1, u(10), 0).unwrap();
        pool.add(t2, u(10), 0).unwrap();
        pool.add(t3, u(10), 0).unwrap();

        let sel = pool.select_for_block(10, &HashMap::new(), u(10));
        assert_eq!(sel.len(), 3);
        // t2 et t3 avant t1 ; t2 avant t3 (arrivée).
        let s2 = recover_sender(&sel[0].tx).unwrap();
        let s3 = recover_sender(&sel[1].tx).unwrap();
        let s1 = recover_sender(&sel[2].tx).unwrap();
        let exp1 = {
            let vk = sk1.verifying_key();
            let p = vk.to_encoded_point(false);
            let h = keccak256(&p.as_bytes()[1..]);
            let mut a = [0u8; 20];
            a.copy_from_slice(&h.as_bytes()[12..]);
            EvmAddress::from_bytes(a)
        };
        let exp2 = {
            let vk = sk2.verifying_key();
            let p = vk.to_encoded_point(false);
            let h = keccak256(&p.as_bytes()[1..]);
            let mut a = [0u8; 20];
            a.copy_from_slice(&h.as_bytes()[12..]);
            EvmAddress::from_bytes(a)
        };
        let exp3 = {
            let vk = sk3.verifying_key();
            let p = vk.to_encoded_point(false);
            let h = keccak256(&p.as_bytes()[1..]);
            let mut a = [0u8; 20];
            a.copy_from_slice(&h.as_bytes()[12..]);
            EvmAddress::from_bytes(a)
        };
        assert_eq!(s2, exp2);
        assert_eq!(s3, exp3);
        assert_eq!(s1, exp1);
    }

    #[test]
    fn select_respects_nonce_dependencies() {
        let sk = signing_key([0x42u8; 32]);
        let mut pool = EvmMempool::default();
        let (t2, _) = signed_legacy(&sk, 2, 100);
        let (t0, _) = signed_legacy(&sk, 0, 10);
        let (t1, _) = signed_legacy(&sk, 1, 10);
        pool.add(t2, u(0), 0).unwrap();
        pool.add(t0, u(0), 0).unwrap();
        pool.add(t1, u(0), 0).unwrap();

        let sel = pool.select_for_block(10, &HashMap::new(), u(0));
        assert_eq!(sel.len(), 2);
        assert_eq!(sel[0].tx.nonce(), 0);
        assert_eq!(sel[1].tx.nonce(), 1);
    }

    #[test]
    fn select_respects_base_nonces() {
        let sk = signing_key([0x42u8; 32]);
        let mut pool = EvmMempool::default();
        let (t5, _) = signed_legacy(&sk, 5, 100);
        let (t6, _) = signed_legacy(&sk, 6, 100);
        let sender = recover_sender(&t5).unwrap();
        pool.add(t5, u(0), 0).unwrap();
        pool.add(t6, u(0), 0).unwrap();

        let mut base = HashMap::new();
        base.insert(sender, 5u64);
        let sel = pool.select_for_block(10, &base, u(0));
        assert_eq!(sel.len(), 2);
        assert_eq!(sel[0].tx.nonce(), 5);
        assert_eq!(sel[1].tx.nonce(), 6);
    }

    #[test]
    fn pruning_removes_applied() {
        let sk = signing_key([0x42u8; 32]);
        let mut pool = EvmMempool::default();
        let (t0, _) = signed_legacy(&sk, 0, 100);
        let (t1, _) = signed_legacy(&sk, 1, 100);
        let (t2, _) = signed_legacy(&sk, 2, 100);
        let sender = recover_sender(&t0).unwrap();
        pool.add(t0, u(0), 0).unwrap();
        pool.add(t1, u(0), 0).unwrap();
        pool.add(t2, u(0), 0).unwrap();

        let mut mins = HashMap::new();
        mins.insert(sender, 2u64);
        let removed = pool.prune_below_nonces(&mins);
        assert_eq!(removed, 2);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn eviction_by_base_fee() {
        let sk1 = signing_key([0x01u8; 32]);
        let sk2 = signing_key([0x02u8; 32]);
        let mut pool = EvmMempool::default();
        let (t1, _) = signed_legacy(&sk1, 0, 20);
        let (t2, _) = signed_legacy(&sk2, 0, 50);
        pool.add(t1, u(0), 0).unwrap();
        pool.add(t2, u(0), 0).unwrap();

        let removed = pool.evict_below_base_fee(u(30));
        assert_eq!(removed, 1);
        assert_eq!(pool.len(), 1);
    }
}
