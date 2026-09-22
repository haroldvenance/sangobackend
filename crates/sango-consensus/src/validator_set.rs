//! Ensemble actif de validateurs.

use std::collections::BTreeMap;

use sango_primitives::{NativeAddress, PublicKey};

use crate::error::ConsensusError;

/// Validateur du set actif.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Validator {
    /// Adresse native.
    pub address: NativeAddress,
    /// Clé publique Ed25519.
    pub public_key: PublicKey,
    /// Puissance de vote (`self_stake + delegated_stake`), en base units.
    pub voting_power: u128,
}

/// Ensemble actif de validateurs.
///
/// L'ordre canonique est l'ordre croissant des adresses. Le set est construit
/// une fois par epoch et ne change pas jusqu'à la frontière suivante.
#[derive(Clone, Debug)]
pub struct ValidatorSet {
    by_address: BTreeMap<NativeAddress, Validator>,
    total_power: u128,
}

impl ValidatorSet {
    /// Construit un validator set.
    ///
    /// # Erreurs
    ///
    /// - [`ConsensusError::EmptyValidatorSet`] si la liste est vide.
    /// - [`ConsensusError::DuplicateValidator`] si deux adresses sont égales.
    /// - [`ConsensusError::ZeroPowerValidator`] si un voting power est nul.
    /// - [`ConsensusError::ZeroVotingPower`] si la somme est nulle (cas
    ///   théoriquement impossible si tous les validators ont un pouvoir > 0,
    ///   mais vérifié par prudence).
    pub fn new(validators: Vec<Validator>) -> Result<Self, ConsensusError> {
        if validators.is_empty() {
            return Err(ConsensusError::EmptyValidatorSet);
        }

        let mut by_address = BTreeMap::new();
        let mut total_power: u128 = 0;

        for v in validators {
            if v.voting_power == 0 {
                return Err(ConsensusError::ZeroPowerValidator(v.address));
            }
            if by_address.contains_key(&v.address) {
                return Err(ConsensusError::DuplicateValidator(v.address));
            }
            total_power = total_power
                .checked_add(v.voting_power)
                .ok_or(ConsensusError::ZeroVotingPower)?;
            by_address.insert(v.address, v);
        }

        if total_power == 0 {
            return Err(ConsensusError::ZeroVotingPower);
        }

        Ok(Self {
            by_address,
            total_power,
        })
    }

    /// Puissance totale du set.
    #[must_use]
    pub fn total_power(&self) -> u128 {
        self.total_power
    }

    /// Nombre de validateurs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_address.len()
    }

    /// Vrai si le set est vide (ne devrait jamais arriver, `.new` rejette).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_address.is_empty()
    }

    /// Itération sur les validateurs, dans l'ordre croissant des adresses.
    pub fn iter(&self) -> impl Iterator<Item = &Validator> {
        self.by_address.values()
    }

    /// Accès direct par adresse.
    #[must_use]
    pub fn get(&self, address: &NativeAddress) -> Option<&Validator> {
        self.by_address.get(address)
    }

    /// Vrai si `power` atteint le quorum strict de `> 2/3` de la puissance
    /// totale.
    ///
    /// `power * 3 > total * 2`.
    #[must_use]
    pub fn has_quorum(&self, power: u128) -> bool {
        power.saturating_mul(3) > self.total_power.saturating_mul(2)
    }

    /// Puissance minimale pour atteindre le quorum (`floor(2/3 * total) + 1`).
    #[must_use]
    pub fn quorum_power(&self) -> u128 {
        (self.total_power.saturating_mul(2) / 3).saturating_add(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> NativeAddress {
        NativeAddress::from_bytes([b; 20])
    }

    fn validator(b: u8, power: u128) -> Validator {
        Validator {
            address: addr(b),
            public_key: PublicKey::from_bytes([b; 32]),
            voting_power: power,
        }
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(
            ValidatorSet::new(vec![]).unwrap_err(),
            ConsensusError::EmptyValidatorSet
        );
    }

    #[test]
    fn rejects_zero_power() {
        let err = ValidatorSet::new(vec![validator(0xaa, 0)]).unwrap_err();
        assert!(matches!(err, ConsensusError::ZeroPowerValidator(_)));
    }

    #[test]
    fn rejects_duplicates() {
        let err = ValidatorSet::new(vec![validator(0xaa, 100), validator(0xaa, 200)]).unwrap_err();
        assert!(matches!(err, ConsensusError::DuplicateValidator(_)));
    }

    #[test]
    fn computes_total_power() {
        let s = ValidatorSet::new(vec![
            validator(0xaa, 100),
            validator(0xbb, 200),
            validator(0xcc, 300),
        ])
        .unwrap();
        assert_eq!(s.total_power(), 600);
        assert_eq!(s.len(), 3);
    }

    #[test]
    fn iter_is_sorted_by_address() {
        let s = ValidatorSet::new(vec![
            validator(0xcc, 100),
            validator(0xaa, 100),
            validator(0xbb, 100),
        ])
        .unwrap();
        let addresses: Vec<_> = s.iter().map(|v| v.address).collect();
        assert_eq!(addresses, vec![addr(0xaa), addr(0xbb), addr(0xcc)]);
    }

    #[test]
    fn lookup_by_address() {
        let s = ValidatorSet::new(vec![validator(0xaa, 100)]).unwrap();
        assert!(s.get(&addr(0xaa)).is_some());
        assert!(s.get(&addr(0xbb)).is_none());
    }

    #[test]
    fn quorum_power_examples() {
        // total = 100 → floor(200/3) + 1 = 66 + 1 = 67.
        let s = ValidatorSet::new(vec![validator(0xaa, 100)]).unwrap();
        assert_eq!(s.quorum_power(), 67);

        // total = 3 → floor(6/3) + 1 = 2 + 1 = 3.
        let s = ValidatorSet::new(vec![
            validator(0xaa, 1),
            validator(0xbb, 1),
            validator(0xcc, 1),
        ])
        .unwrap();
        assert_eq!(s.quorum_power(), 3);
    }

    #[test]
    fn has_quorum_just_below_and_at_threshold() {
        // total = 100 → quorum = 67.
        let s = ValidatorSet::new(vec![validator(0xaa, 100)]).unwrap();
        assert!(!s.has_quorum(66));
        assert!(s.has_quorum(67));
        assert!(s.has_quorum(100));
    }

    #[test]
    fn has_quorum_strictly_more_than_two_thirds() {
        // total = 3, need > 2 → 3.
        let s = ValidatorSet::new(vec![
            validator(0xaa, 1),
            validator(0xbb, 1),
            validator(0xcc, 1),
        ])
        .unwrap();
        assert!(!s.has_quorum(2)); // exactly 2/3, not enough
        assert!(s.has_quorum(3));
    }

    #[test]
    fn has_quorum_zero_total_rejected_by_new() {
        // Couvert par `rejects_zero_power` / `EmptyValidatorSet`.
    }
}
