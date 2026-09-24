//! Namespaces d'état natif Sango.

/// Namespace logique d'une entrée d'état natif.
///
/// Le `u8` du variant est **normatif** : c'est le premier byte de la clé
/// logique avant hashage. Ne jamais réordonner ni renuméroter.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Namespace {
    /// Comptes natifs (`Account`).
    NativeAccount = 0x01,
    /// Validateurs (self-stake, clé publique, commission).
    Validator = 0x02,
    /// Délégations.
    Delegation = 0x03,
    /// État de staking (bonded/unbonding).
    Staking = 0x04,
    /// Evidence (double-sign, downtime).
    Evidence = 0x05,
    /// Gouvernance.
    Governance = 0x06,
    /// Métadonnées de chaîne.
    Metadata = 0x07,
    /// Événements d'unbonding en attente de maturation.
    ///
    /// Clé = `id_u64_be`. Valeur = `PendingUnbonding` encodé.
    Unbonding = 0x08,
}

impl Namespace {
    /// Byte canonique du namespace.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::Namespace;

    #[test]
    fn tags_match_spec() {
        assert_eq!(Namespace::NativeAccount.tag(), 0x01);
        assert_eq!(Namespace::Validator.tag(), 0x02);
        assert_eq!(Namespace::Delegation.tag(), 0x03);
        assert_eq!(Namespace::Staking.tag(), 0x04);
        assert_eq!(Namespace::Evidence.tag(), 0x05);
        assert_eq!(Namespace::Governance.tag(), 0x06);
        assert_eq!(Namespace::Metadata.tag(), 0x07);
        assert_eq!(Namespace::Unbonding.tag(), 0x08);
    }
}
