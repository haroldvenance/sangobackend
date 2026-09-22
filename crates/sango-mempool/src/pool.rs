//! Mempool : pool de transactions en attente d'inclusion.

use std::collections::{BTreeMap, HashMap, HashSet};

use sango_primitives::{Hash32, NativeAddress};
use sango_types::Transaction;

use crate::error::MempoolError;

/// Configuration du mempool.
#[derive(Clone, Copy, Debug)]
pub struct MempoolConfig {
    /// Capacité maximale en nombre de transactions.
    pub max_transactions: usize,
    /// Nombre maximum de transactions par émetteur.
    pub max_per_sender: usize,
    /// Fenêtre de nonces futurs acceptés (`current + max_nonce_gap`).
    pub max_nonce_gap: u64,
    /// Bump de remplacement en basis points (`1_000` = +10 %).
    pub replacement_bump_bps: u32,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_transactions: 100_000,
            max_per_sender: 64,
            max_nonce_gap: 64,
            replacement_bump_bps: 1_000,
        }
    }
}

/// Entrée du mempool.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MempoolEntry {
    /// Transaction.
    pub tx: Transaction,
    /// Hash de la transaction.
    pub tx_hash: Hash32,
    /// Prix effectif (min(max_fee, base_fee + priority_fee)) au moment
    /// de l'admission.
    pub effective_price: u128,
    /// Ordre d'arrivée (timestamp logique interne).
    pub arrival: u64,
}

/// Mempool.
#[derive(Debug)]
pub struct Mempool {
    config: MempoolConfig,
    /// Entrées par hash.
    by_hash: HashMap<Hash32, MempoolEntry>,
    /// Index secondaire : `(sender, nonce) → hash`.
    by_sender_nonce: BTreeMap<(NativeAddress, u64), Hash32>,
    /// Ordre d'arrivée, monotone.
    arrival_counter: u64,
    /// Nombre de transactions par sender.
    per_sender_count: HashMap<NativeAddress, usize>,
}

impl Mempool {
    /// Crée un mempool avec la configuration donnée.
    #[must_use]
    pub fn new(config: MempoolConfig) -> Self {
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
    pub fn config(&self) -> &MempoolConfig {
        &self.config
    }

    /// Vrai si le hash est présent.
    #[must_use]
    pub fn contains(&self, hash: &Hash32) -> bool {
        self.by_hash.contains_key(hash)
    }

    /// Lit une entrée par hash.
    #[must_use]
    pub fn get(&self, hash: &Hash32) -> Option<&MempoolEntry> {
        self.by_hash.get(hash)
    }

    /// Admet une transaction.
    ///
    /// ## Règles
    ///
    /// - Doublon de hash → [`MempoolError::Duplicate`].
    /// - Capacité globale atteinte → [`MempoolError::Full`].
    /// - Capacité par sender atteinte → [`MempoolError::Full`].
    /// - `max_fee < base_fee` → [`MempoolError::MaxFeeBelowBaseFee`].
    /// - Nonce déjà occupé par une autre tx :
    ///   - si la nouvelle offre un bump `>= replacement_bump_bps`, elle
    ///     remplace l'ancienne ;
    ///   - sinon → [`MempoolError::ReplacementFeeTooLow`].
    pub fn add(
        &mut self,
        tx: Transaction,
        base_fee: u128,
        sender_nonce: u64,
    ) -> Result<Hash32, MempoolError> {
        let tx_hash = tx.hash();

        if self.by_hash.contains_key(&tx_hash) {
            return Err(MempoolError::Duplicate(tx_hash));
        }

        if tx.max_fee < base_fee {
            return Err(MempoolError::MaxFeeBelowBaseFee {
                max_fee: tx.max_fee,
                base_fee,
            });
        }

        // Fenêtre de nonce.
        let min_nonce = sender_nonce;
        let max_nonce = sender_nonce.saturating_add(self.config.max_nonce_gap);
        if tx.nonce < min_nonce {
            return Err(MempoolError::NonceTooLow {
                expected: min_nonce,
                got: tx.nonce,
            });
        }
        if tx.nonce > max_nonce {
            return Err(MempoolError::NonceTooHigh {
                expected: max_nonce,
                got: tx.nonce,
            });
        }

        // Prix effectif.
        let effective_price = tx.max_fee.min(base_fee.saturating_add(tx.priority_fee));

        // Collision de nonce pour ce sender ?
        let key = (tx.sender, tx.nonce);
        if let Some(existing_hash) = self.by_sender_nonce.get(&key).copied() {
            let existing = self.by_hash.get(&existing_hash).expect("index consistant");
            let bump_bps = self.config.replacement_bump_bps as u128;
            let min_required = existing.effective_price.saturating_mul(10_000 + bump_bps) / 10_000;
            if effective_price < min_required {
                return Err(MempoolError::ReplacementFeeTooLow {
                    needed: min_required,
                    got: effective_price,
                });
            }
            // Remplacer : retirer l'ancienne.
            self.remove(&existing_hash);
        }

        // Capacité globale.
        if self.by_hash.len() >= self.config.max_transactions {
            return Err(MempoolError::Full);
        }

        // Capacité par sender.
        let count = self.per_sender_count.entry(tx.sender).or_insert(0);
        if *count >= self.config.max_per_sender {
            return Err(MempoolError::Full);
        }
        *count += 1;

        self.arrival_counter = self.arrival_counter.saturating_add(1);
        let entry = MempoolEntry {
            tx,
            tx_hash,
            effective_price,
            arrival: self.arrival_counter,
        };
        self.by_hash.insert(tx_hash, entry);
        self.by_sender_nonce.insert(key, tx_hash);
        Ok(tx_hash)
    }

    /// Retire une transaction par hash.
    pub fn remove(&mut self, hash: &Hash32) -> Option<MempoolEntry> {
        let entry = self.by_hash.remove(hash)?;
        self.by_sender_nonce
            .remove(&(entry.tx.sender, entry.tx.nonce));
        if let Some(count) = self.per_sender_count.get_mut(&entry.tx.sender) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.per_sender_count.remove(&entry.tx.sender);
            }
        }
        Some(entry)
    }

    /// Sélectionne jusqu'à `max_count` transactions pour un bloc.
    ///
    /// Ordre de tri : `effective_price` décroissant, puis `arrival`
    /// croissant (FIFO à prix égal). Les dépendances de nonce sont
    /// respectées : pour un même sender, on ne peut inclure un nonce `n`
    /// sans avoir inclus `n-1` (dans la même sélection ou déjà appliqué).
    #[must_use]
    pub fn select_for_block(
        &self,
        max_count: usize,
        base_nonces: &HashMap<NativeAddress, u64>,
    ) -> Vec<MempoolEntry> {
        let mut candidates: Vec<&MempoolEntry> = self.by_hash.values().collect();
        candidates.sort_by(|a, b| {
            b.effective_price
                .cmp(&a.effective_price)
                .then(a.arrival.cmp(&b.arrival))
        });

        let mut selected = Vec::new();
        let mut next_nonce: HashMap<NativeAddress, u64> = base_nonces.clone();

        for entry in candidates {
            if selected.len() >= max_count {
                break;
            }
            let expected = next_nonce.get(&entry.tx.sender).copied().unwrap_or(0);
            if entry.tx.nonce == expected {
                next_nonce.insert(entry.tx.sender, expected + 1);
                selected.push(entry.clone());
            } else if entry.tx.nonce < expected {
                // Déjà appliqué ou en retard.
                continue;
            }
            // Sinon : nonce futur, ne peut pas être sélectionné tant que les
            // nonces intermédiaires n'ont pas été pris.
        }
        selected
    }

    /// Retire toutes les transactions dont le nonce est strictement
    /// inférieur à `min_nonces[sender]`.
    ///
    /// Utilisé après application d'un bloc pour purger les transactions
    /// déjà incluses.
    pub fn prune_below_nonces(&mut self, min_nonces: &HashMap<NativeAddress, u64>) -> usize {
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

    /// Retire les transactions dont `max_fee < new_base_fee`.
    ///
    /// Utilisé quand la base fee augmente.
    pub fn evict_below_base_fee(&mut self, new_base_fee: u128) -> usize {
        let to_remove: Vec<Hash32> = self
            .by_hash
            .values()
            .filter(|e| e.tx.max_fee < new_base_fee)
            .map(|e| e.tx_hash)
            .collect();
        let count = to_remove.len();
        for hash in to_remove {
            self.remove(&hash);
        }
        count
    }

    /// Retourne les hashes de toutes les transactions, triés par ordre de
    /// sélection (prix décroissant, FIFO).
    #[must_use]
    pub fn ordered_hashes(&self) -> Vec<Hash32> {
        let mut candidates: Vec<&MempoolEntry> = self.by_hash.values().collect();
        candidates.sort_by(|a, b| {
            b.effective_price
                .cmp(&a.effective_price)
                .then(a.arrival.cmp(&b.arrival))
        });
        candidates.into_iter().map(|e| e.tx_hash).collect()
    }

    /// Hashes connus.
    #[must_use]
    pub fn hashes(&self) -> HashSet<Hash32> {
        self.by_hash.keys().copied().collect()
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new(MempoolConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sango_primitives::{Amount, ChainId32, Signature};
    use sango_types::TxKind;

    fn chain() -> ChainId32 {
        ChainId32::from_bytes([0x11; 32])
    }

    fn addr(b: u8) -> NativeAddress {
        NativeAddress::from_bytes([b; 20])
    }

    fn tx(sender: NativeAddress, nonce: u64, max_fee: u128, priority: u128) -> Transaction {
        Transaction {
            version: 1,
            chain_id: chain(),
            nonce,
            sender,
            public_key: None,
            gas_limit: 21_000,
            max_fee,
            priority_fee: priority,
            value: Amount::from_base_units(0),
            tx_kind: TxKind::Transfer,
            recipient: Some(addr(0xff)),
            data: Vec::new(),
            signature: Signature::ZERO,
        }
    }

    #[test]
    fn add_and_remove() {
        let mut pool = Mempool::default();
        let t = tx(addr(0xaa), 0, 20, 2);
        let h = t.hash();
        pool.add(t, 10, 0).unwrap();
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&h));
        pool.remove(&h);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn duplicate_rejected() {
        let mut pool = Mempool::default();
        let t = tx(addr(0xaa), 0, 20, 2);
        pool.add(t.clone(), 10, 0).unwrap();
        let err = pool.add(t, 10, 0).unwrap_err();
        assert!(matches!(err, MempoolError::Duplicate(_)));
    }

    #[test]
    fn max_fee_below_base_rejected() {
        let mut pool = Mempool::default();
        let t = tx(addr(0xaa), 0, 5, 1);
        let err = pool.add(t, 10, 0).unwrap_err();
        assert!(matches!(err, MempoolError::MaxFeeBelowBaseFee { .. }));
    }

    #[test]
    fn nonce_too_low_rejected() {
        let mut pool = Mempool::default();
        let t = tx(addr(0xaa), 0, 20, 2);
        let err = pool.add(t, 10, 5).unwrap_err();
        assert!(matches!(err, MempoolError::NonceTooLow { .. }));
    }

    #[test]
    fn nonce_too_high_rejected() {
        let mut pool = Mempool::default();
        let t = tx(addr(0xaa), 100, 20, 2);
        let err = pool.add(t, 10, 0).unwrap_err();
        assert!(matches!(err, MempoolError::NonceTooHigh { .. }));
    }

    #[test]
    fn replacement_with_insufficient_bump_rejected() {
        let mut pool = Mempool::default();
        pool.add(tx(addr(0xaa), 0, 20, 2), 10, 0).unwrap();
        // Même nonce, prix effectif à peine supérieur → rejeté.
        // effective_price initial = min(20, 10+2) = 12.
        // besoin = 12 * 11000 / 10000 = 13.2 → 13.
        let err = pool.add(tx(addr(0xaa), 0, 13, 0), 10, 0).unwrap_err();
        assert!(matches!(err, MempoolError::ReplacementFeeTooLow { .. }));
    }

    #[test]
    fn replacement_with_sufficient_bump_accepted() {
        let mut pool = Mempool::default();
        let h1 = pool.add(tx(addr(0xaa), 0, 20, 2), 10, 0).unwrap();
        // Nouvelle tx avec max_fee 25, priority 2 → effective = min(25, 12) = 12.
        // Hmm 12 < 13 : rejeté. Prenons max_fee 30, priority 3 :
        // effective = min(30, 13) = 13 >= 13 → accepté.
        let h2 = pool.add(tx(addr(0xaa), 0, 30, 3), 10, 0).unwrap();
        assert_ne!(h1, h2);
        assert_eq!(pool.len(), 1);
        assert!(!pool.contains(&h1));
        assert!(pool.contains(&h2));
    }

    #[test]
    fn per_sender_capacity() {
        let config = MempoolConfig {
            max_per_sender: 2,
            ..Default::default()
        };
        let mut pool = Mempool::new(config);
        pool.add(tx(addr(0xaa), 0, 100, 10), 0, 0).unwrap();
        pool.add(tx(addr(0xaa), 1, 100, 10), 0, 0).unwrap();
        let err = pool.add(tx(addr(0xaa), 2, 100, 10), 0, 0).unwrap_err();
        assert!(matches!(err, MempoolError::Full));
    }

    #[test]
    fn global_capacity() {
        let config = MempoolConfig {
            max_transactions: 2,
            ..Default::default()
        };
        let mut pool = Mempool::new(config);
        pool.add(tx(addr(0xaa), 0, 100, 0), 0, 0).unwrap();
        pool.add(tx(addr(0xbb), 0, 100, 0), 0, 0).unwrap();
        let err = pool.add(tx(addr(0xcc), 0, 100, 0), 0, 0).unwrap_err();
        assert!(matches!(err, MempoolError::Full));
    }

    #[test]
    fn select_orders_by_price_then_arrival() {
        let mut pool = Mempool::default();
        // Ordre d'arrivée : A (prix 12), B (prix 15), C (prix 15).
        pool.add(tx(addr(0xaa), 0, 20, 2), 10, 0).unwrap(); // eff=12
        pool.add(tx(addr(0xbb), 0, 30, 5), 10, 0).unwrap(); // eff=15
        pool.add(tx(addr(0xcc), 0, 30, 5), 10, 0).unwrap(); // eff=15

        let base = HashMap::new();
        let selected = pool.select_for_block(10, &base);
        assert_eq!(selected.len(), 3);
        // B et C (prix 15) avant A (prix 12), B avant C (arrivée).
        assert_eq!(selected[0].tx.sender, addr(0xbb));
        assert_eq!(selected[1].tx.sender, addr(0xcc));
        assert_eq!(selected[2].tx.sender, addr(0xaa));
    }

    #[test]
    fn select_respects_nonce_dependencies() {
        let mut pool = Mempool::default();
        // Nonce 2 d'abord (prix élevé), puis 0 et 1 (prix bas).
        pool.add(tx(addr(0xaa), 2, 100, 10), 0, 0).unwrap();
        pool.add(tx(addr(0xaa), 0, 15, 1), 0, 0).unwrap();
        pool.add(tx(addr(0xaa), 1, 15, 1), 0, 0).unwrap();

        let base = HashMap::new();
        let selected = pool.select_for_block(10, &base);
        // Seuls 0 et 1 sont sélectionnables (2 doit attendre).
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].tx.nonce, 0);
        assert_eq!(selected[1].tx.nonce, 1);
    }

    #[test]
    fn select_respects_base_nonces() {
        let mut pool = Mempool::default();
        pool.add(tx(addr(0xaa), 5, 100, 0), 0, 0).unwrap();
        pool.add(tx(addr(0xaa), 6, 100, 0), 0, 0).unwrap();

        let mut base = HashMap::new();
        base.insert(addr(0xaa), 5u64);
        let selected = pool.select_for_block(10, &base);
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].tx.nonce, 5);
        assert_eq!(selected[1].tx.nonce, 6);
    }

    #[test]
    fn prune_below_nonces_removes_applied() {
        let mut pool = Mempool::default();
        pool.add(tx(addr(0xaa), 0, 100, 0), 0, 0).unwrap();
        pool.add(tx(addr(0xaa), 1, 100, 0), 0, 0).unwrap();
        pool.add(tx(addr(0xaa), 2, 100, 0), 0, 0).unwrap();

        let mut mins = HashMap::new();
        mins.insert(addr(0xaa), 2u64);
        let removed = pool.prune_below_nonces(&mins);
        assert_eq!(removed, 2);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn evict_below_base_fee_removes_cheap_txs() {
        let mut pool = Mempool::default();
        pool.add(tx(addr(0xaa), 0, 20, 0), 10, 0).unwrap();
        pool.add(tx(addr(0xbb), 0, 5, 0), 0, 0).unwrap();
        let removed = pool.evict_below_base_fee(10);
        assert_eq!(removed, 1);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn clear_empties_pool() {
        let mut pool = Mempool::default();
        pool.add(tx(addr(0xaa), 0, 100, 0), 0, 0).unwrap();
        pool.add(tx(addr(0xbb), 0, 100, 0), 0, 0).unwrap();
        pool.clear();
        assert!(pool.is_empty());
    }
}
