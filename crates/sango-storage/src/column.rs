//! Colonnes logiques du stockage.
//!
//! Le Freeze spécifie les espaces logiques suivants (section 55) :
//! `blocks`, `block_headers`, `transactions`, `receipts`, `state`,
//! `validators`, `staking`, `evidence`, `consensus`, `metadata`.
//!
//! Ces noms sont **normatifs** : ce sont les noms des *column families*
//! RocksDB. Ils ne doivent pas changer sans modification de la spec.

/// Colonne logique RocksDB.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Column {
    /// Blocs complets indexés par `block_hash`.
    Blocks,
    /// En-têtes de blocs indexés par `block_hash`.
    BlockHeaders,
    /// Index hauteur → hash de bloc (`u64 LE` → `Hash32`).
    BlockHeights,
    /// Transactions indexées par `tx_hash`.
    Transactions,
    /// Receipts indexés par `tx_hash`.
    Receipts,
    /// Localisation des transactions (index secondaire).
    ///
    /// Clé = `tx_hash` (32 bytes).
    /// Valeur = `height(8 LE) || block_hash(32) || tx_index(4 LE) || tag(1)`.
    ///
    /// `tag` = `0x01` (native) ou `0x02` (EVM). Permet de retrouver
    /// `block_height`, `block_hash` et la position dans le bloc à
    /// partir du hash de la tx.
    TxLocations,
    /// Index `sender → [tx_hash]` pour les txs natives.
    ///
    /// Clé = `sender(20) || height_be(8) || tx_index_be(4)` (32 bytes).
    /// Valeur = `tx_hash` (32 bytes).
    ///
    /// Trié byte-lex = trié par `(sender, height, tx_index)`. Pour
    /// paginer « plus récent d'abord », itérer à l'envers sur le
    /// préfixe `sender`.
    TxBySender,
    /// Résultat financier par transaction.
    ///
    /// Clé = `tx_hash` (32 bytes).
    /// Valeur = `TxOutcome` encodé canonique.
    ///
    /// Contient les effets métier persistants (`claimedRewards`,
    /// `unbondAmount`, `unbondMatureAt`) — voir `sango-types::TxOutcome`.
    TxOutcomes,
    /// Entrées du SMT d'état natif indexées par `key_hash`.
    StateNative,
    /// État validateurs.
    Validators,
    /// État de staking / délégations.
    Staking,
    /// Evidence (double-sign, downtime).
    Evidence,
    /// État consensus (lock, valid_round, etc.).
    Consensus,
    /// Comptes EVM (state trie Ethereum).
    ///
    /// Clé = `Keccak256(evm_address)` (32 bytes).
    /// Valeur = RLP `[nonce, balance, storage_root, code_hash]`.
    EvmAccounts,
    /// Storage EVM par compte.
    ///
    /// Clé = `evm_address(20 bytes) || slot_hash(32 bytes)` (52 bytes).
    /// Valeur = RLP `value_minimal_be`.
    ///
    /// Le préfixe `evm_address` est **purement physique** : il identifie le
    /// compte propriétaire dans le KV store. Il ne fait **pas** partie de
    /// la clé du storage MPT (qui est `Keccak256(slot_be_32)`).
    ///
    /// **Pourquoi l'adresse en clair et pas `Keccak256(addr)` ?** Parce
    /// que `Keccak256` n'est pas inversible, et le restore au démarrage a
    /// besoin de l'adresse pour reconstruire l'`EvmState`.
    EvmStorage,
    /// Code EVM (bytecode de contrat).
    ///
    /// Clé = `code_hash` (32 bytes) = `Keccak256(bytecode)`.
    /// Valeur = bytecode brut (non préfixé, non RLP).
    ///
    /// **Invariant** : `Keccak256(value) == key`. Toute entrée qui ne
    /// respecte pas cet invariant doit être rejetée à la lecture.
    EvmCode,
    /// Métadonnées de chaîne (dernier bloc finalisé, etc.).
    Metadata,
}

impl Column {
    /// Toutes les colonnes dans l'ordre canonique.
    pub const ALL: &'static [Column] = &[
        Column::Blocks,
        Column::BlockHeaders,
        Column::BlockHeights,
        Column::Transactions,
        Column::Receipts,
        Column::TxLocations,
        Column::TxBySender,
        Column::TxOutcomes,
        Column::StateNative,
        Column::Validators,
        Column::Staking,
        Column::Evidence,
        Column::Consensus,
        Column::EvmAccounts,
        Column::EvmStorage,
        Column::EvmCode,
        Column::Metadata,
    ];

    /// Nom canonique de la colonne (utilisé comme nom de column family RocksDB).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Column::Blocks => "blocks",
            Column::BlockHeaders => "block_headers",
            Column::BlockHeights => "block_heights",
            Column::Transactions => "transactions",
            Column::Receipts => "receipts",
            Column::TxLocations => "tx_locations",
            Column::TxBySender => "tx_by_sender",
            Column::TxOutcomes => "tx_outcomes",
            Column::StateNative => "state_native",
            Column::Validators => "validators",
            Column::Staking => "staking",
            Column::Evidence => "evidence",
            Column::Consensus => "consensus",
            Column::EvmAccounts => "evm_accounts",
            Column::EvmStorage => "evm_storage",
            Column::EvmCode => "evm_code",
            Column::Metadata => "metadata",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Column;
    use std::collections::HashSet;

    #[test]
    fn names_are_unique() {
        let mut set = HashSet::new();
        for c in Column::ALL {
            assert!(set.insert(c.name()), "duplicate column name: {}", c.name());
        }
    }

    #[test]
    fn names_match_freeze() {
        assert_eq!(Column::Blocks.name(), "blocks");
        assert_eq!(Column::BlockHeaders.name(), "block_headers");
        assert_eq!(Column::BlockHeights.name(), "block_heights");
        assert_eq!(Column::Transactions.name(), "transactions");
        assert_eq!(Column::Receipts.name(), "receipts");
        assert_eq!(Column::TxLocations.name(), "tx_locations");
        assert_eq!(Column::TxBySender.name(), "tx_by_sender");
        assert_eq!(Column::TxOutcomes.name(), "tx_outcomes");
        assert_eq!(Column::StateNative.name(), "state_native");
        assert_eq!(Column::Validators.name(), "validators");
        assert_eq!(Column::Staking.name(), "staking");
        assert_eq!(Column::Evidence.name(), "evidence");
        assert_eq!(Column::Consensus.name(), "consensus");
        assert_eq!(Column::EvmAccounts.name(), "evm_accounts");
        assert_eq!(Column::EvmStorage.name(), "evm_storage");
        assert_eq!(Column::EvmCode.name(), "evm_code");
        assert_eq!(Column::Metadata.name(), "metadata");
    }

    #[test]
    fn all_contains_every_variant() {
        assert_eq!(Column::ALL.len(), 17);
    }
}
