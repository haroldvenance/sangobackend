//! Newtypes numériques (`u64`) pour éviter les confusions d'unités.

macro_rules! define_u64_newtype {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
        pub struct $name(u64);

        impl $name {
            /// Valeur zéro.
            pub const ZERO: Self = Self(0);

            /// Construit à partir d'un `u64`.
            #[must_use]
            pub const fn new(value: u64) -> Self {
                Self(value)
            }

            /// Retourne la valeur `u64`.
            #[must_use]
            pub const fn get(self) -> u64 {
                self.0
            }

            /// Addition vérifiée.
            #[must_use]
            pub const fn checked_add(self, rhs: u64) -> Option<Self> {
                match self.0.checked_add(rhs) {
                    Some(v) => Some(Self(v)),
                    None => None,
                }
            }
        }

        impl From<u64> for $name {
            fn from(v: u64) -> Self {
                Self(v)
            }
        }

        impl From<$name> for u64 {
            fn from(v: $name) -> Self {
                v.0
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

define_u64_newtype!(
    Height,
    "Hauteur de bloc, strictement croissante le long de la chaîne."
);

define_u64_newtype!(
    Round,
    "Round de consensus à une hauteur donnée. `0` pour le round nominal."
);

define_u64_newtype!(
    Epoch,
    "Index d'epoch. Chaque epoch couvre `EPOCH_LENGTH` blocs (V1 : 1000)."
);

#[cfg(test)]
mod tests {
    use super::{Epoch, Height, Round};

    #[test]
    fn basic_construction() {
        assert_eq!(Height::new(42).get(), 42);
        assert_eq!(Round::new(3).get(), 3);
        assert_eq!(Epoch::new(7).get(), 7);
    }

    #[test]
    fn checked_add_overflow() {
        assert_eq!(Height::new(1).checked_add(2), Some(Height::new(3)));
        assert_eq!(Height::new(u64::MAX).checked_add(1), None);
    }

    #[test]
    fn display() {
        assert_eq!(Height::new(10).to_string(), "10");
    }
}
