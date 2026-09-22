//! Clés canoniques du namespace `Metadata`.
//!
//! Le namespace `Metadata` porte les compteurs globaux de chaîne qui
//! doivent faire partie du `native_state_root` :
//!
//! - [`MetadataKey::TotalBurned`] : cumul des SANGO brûlés (base units) ;
//! - [`MetadataKey::TotalGasUsed`] : cumul du gas consommé.
//!
//! ## Ordre canonique
//!
//! Le tag `u8` est **normatif** : il constitue le premier (et unique) byte
//! de l'identifiant logique avant hashage :
//!
//! ```text
//! key_hash = Keccak256("SANGO/STATE/KEY/V1" || namespace_u8 || tag_u8)
//! ```
//!
//! Ne jamais renuméroter ni réutiliser un tag.

/// Clé canonique du namespace `Metadata`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum MetadataKey {
    /// Cumul des SANGO brûlés, en base units (`u128` LE).
    TotalBurned = 0x01,
    /// Cumul du gas consommé (`u64` LE).
    TotalGasUsed = 0x02,
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
        let all = [MetadataKey::TotalBurned, MetadataKey::TotalGasUsed];
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
    }
}
