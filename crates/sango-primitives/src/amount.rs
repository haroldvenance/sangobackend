//! Montants en base units SANGO.

/// Nombre de base units dans 1 SANGO.
///
/// V1 utilise **7 décimales** : `1 SANGO = 10_000_000 base units`.
pub const BASE_UNITS_PER_SANGO: u128 = 10_000_000;

/// Offre maximale en base units.
///
/// `1_000_000_000 SANGO × 10_000_000 = 10^16 base units`.
pub const MAX_SUPPLY_BASE: u128 = 10_000_000_000_000_000;

/// Quantité de SANGO exprimée en base units.
///
/// Tous les calculs monétaires du protocole utilisent des entiers.
/// Les nombres flottants sont **interdits**.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Amount(u128);

impl Amount {
    /// Zéro SANGO.
    pub const ZERO: Self = Self(0);

    /// Construit à partir d'un nombre de base units.
    #[must_use]
    pub const fn from_base_units(v: u128) -> Self {
        Self(v)
    }

    /// Retourne le nombre de base units.
    #[must_use]
    pub const fn base_units(self) -> u128 {
        self.0
    }

    /// Construit à partir d'un nombre entier de SANGO.
    ///
    /// Retourne `None` si la multiplication déborde `u128`.
    #[must_use]
    pub const fn from_sango(v: u128) -> Option<Self> {
        match v.checked_mul(BASE_UNITS_PER_SANGO) {
            Some(b) => Some(Self(b)),
            None => None,
        }
    }

    /// Addition vérifiée.
    #[must_use]
    pub const fn checked_add(self, rhs: Self) -> Option<Self> {
        match self.0.checked_add(rhs.0) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }

    /// Soustraction vérifiée.
    #[must_use]
    pub const fn checked_sub(self, rhs: Self) -> Option<Self> {
        match self.0.checked_sub(rhs.0) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }

    /// Vrai si le montant est nul.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl From<u128> for Amount {
    fn from(v: u128) -> Self {
        Self(v)
    }
}

impl From<Amount> for u128 {
    fn from(v: Amount) -> Self {
        v.0
    }
}

impl core::fmt::Display for Amount {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{Amount, BASE_UNITS_PER_SANGO, MAX_SUPPLY_BASE};

    #[test]
    fn constants_are_consistent() {
        assert_eq!(BASE_UNITS_PER_SANGO, 10_000_000);
        assert_eq!(MAX_SUPPLY_BASE, 10_000_000_000_000_000);
        assert_eq!(MAX_SUPPLY_BASE / BASE_UNITS_PER_SANGO, 1_000_000_000);
    }

    #[test]
    fn one_sango() {
        let a = Amount::from_sango(1).unwrap();
        assert_eq!(a.base_units(), BASE_UNITS_PER_SANGO);
    }

    #[test]
    fn max_supply_fits() {
        let a = Amount::from_base_units(MAX_SUPPLY_BASE);
        assert_eq!(a.base_units(), MAX_SUPPLY_BASE);
    }

    #[test]
    fn checked_add_detects_overflow() {
        let a = Amount::from_base_units(u128::MAX);
        assert!(a.checked_add(Amount::from_base_units(1)).is_none());
    }

    #[test]
    fn checked_sub_detects_underflow() {
        let a = Amount::from_base_units(0);
        assert!(a.checked_sub(Amount::from_base_units(1)).is_none());
    }

    #[test]
    fn zero() {
        assert!(Amount::ZERO.is_zero());
        assert_eq!(Amount::default(), Amount::ZERO);
    }
}
