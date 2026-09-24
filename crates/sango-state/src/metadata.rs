//! Clés canoniques du namespace `Metadata`.

/// Clé canonique du namespace `Metadata`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum MetadataKey {
    /// Cumul des SANGO brûlés, en base units (`u128` LE).
    TotalBurned = 0x01,
    /// Cumul du gas consommé (`u64` LE).
    TotalGasUsed = 0x02,
    /// Pointeur vers le dernier bloc appliqué (`ChainTip`).
    ///
    /// Encodage : `u64 (height) || Hash32 (block_hash) || u128 (base_fee)`.
    ChainTip = 0x03,
    /// Cumul des récompenses PoS distribuées (base units, `u128` LE).
    TotalPosRewards = 0x04,
    /// Prochain identifiant d'unbonding (`u64` LE).
    ///
    /// Compteur monotone. Chaque `unbond` / `undelegate` alloue un id et
    /// écrit un `PendingUnbonding` sous `Namespace::Unbonding, id.to_be_bytes()`.
    NextUnbondingId = 0x05,
}

impl MetadataKey {
    /// Byte canonique.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::MetadataKey;

    #[test]
    fn tags_are_unique() {
        let all = [
            MetadataKey::TotalBurned,
            MetadataKey::TotalGasUsed,
            MetadataKey::ChainTip,
            MetadataKey::TotalPosRewards,
            MetadataKey::NextUnbondingId,
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate().skip(i + 1) {
                assert_ne!(a.tag(), b.tag(), "duplicate tag at {i}/{j}");
            }
        }
    }

    #[test]
    fn tags_match_spec() {
        assert_eq!(MetadataKey::TotalBurned.tag(), 0x01);
        assert_eq!(MetadataKey::TotalGasUsed.tag(), 0x02);
        assert_eq!(MetadataKey::ChainTip.tag(), 0x03);
        assert_eq!(MetadataKey::TotalPosRewards.tag(), 0x04);
        assert_eq!(MetadataKey::NextUnbondingId.tag(), 0x05);
    }
}
