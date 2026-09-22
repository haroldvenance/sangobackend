//! Macro interne pour générer des newtypes à taille fixe.

macro_rules! define_fixed_bytes {
    ($name:ident, $len:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
        pub struct $name([u8; $len]);

        impl $name {
            /// Longueur en bytes.
            pub const LEN: usize = $len;

            /// Valeur nulle (tous les bytes à zéro).
            pub const ZERO: Self = Self([0u8; $len]);

            /// Construit à partir d'un tableau de bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            /// Emprunte le tableau sous-jacent.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            /// Consomme et retourne le tableau sous-jacent.
            #[must_use]
            pub const fn to_bytes(self) -> [u8; $len] {
                self.0
            }

            /// Vérifie si la valeur est entièrement nulle.
            #[must_use]
            pub fn is_zero(&self) -> bool {
                self.0.iter().all(|b| *b == 0)
            }

            /// Construit à partir d'une slice de bytes.
            ///
            /// # Erreurs
            ///
            /// Retourne [`PrimitiveError::InvalidLength`] si la slice n'a pas
            /// exactement `$len` bytes.
            pub fn from_slice(bytes: &[u8]) -> Result<Self, $crate::PrimitiveError> {
                if bytes.len() != $len {
                    return Err($crate::PrimitiveError::InvalidLength {
                        expected: $len,
                        actual: bytes.len(),
                    });
                }
                let mut buf = [0u8; $len];
                buf.copy_from_slice(bytes);
                Ok(Self(buf))
            }

            /// Encode en hexadécimal minuscule, sans préfixe `0x`.
            #[must_use]
            pub fn to_hex(self) -> String {
                ::hex::encode(self.0)
            }

            /// Parse une chaîne hexadécimale, avec ou sans préfixe `0x`.
            pub fn from_hex(s: &str) -> Result<Self, $crate::PrimitiveError> {
                let s = s.strip_prefix("0x").unwrap_or(s);
                let bytes = ::hex::decode(s)
                    .map_err(|e| $crate::PrimitiveError::InvalidHex(e.to_string()))?;
                Self::from_slice(&bytes)
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::ZERO
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}({})", stringify!($name), self.to_hex())
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = $crate::PrimitiveError;

            fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                Self::from_slice(value)
            }
        }

        impl From<[u8; $len]> for $name {
            fn from(value: [u8; $len]) -> Self {
                Self(value)
            }
        }

        impl From<$name> for [u8; $len] {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

pub(crate) use define_fixed_bytes;

#[cfg(test)]
mod tests {
    define_fixed_bytes!(TestBytes, 4, "Type de test interne.");

    #[test]
    fn zero_is_zero() {
        assert!(TestBytes::ZERO.is_zero());
        assert_eq!(TestBytes::default(), TestBytes::ZERO);
    }

    #[test]
    fn roundtrip_slice() {
        let v = TestBytes::from_bytes([1, 2, 3, 4]);
        let parsed = TestBytes::from_slice(v.as_bytes()).unwrap();
        assert_eq!(v, parsed);
    }

    #[test]
    fn wrong_length_fails() {
        let err = TestBytes::from_slice(&[1, 2, 3]).unwrap_err();
        matches!(err, crate::PrimitiveError::InvalidLength { .. });
    }

    #[test]
    fn hex_roundtrip() {
        let v = TestBytes::from_bytes([0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(v.to_hex(), "deadbeef");
        assert_eq!(TestBytes::from_hex("deadbeef").unwrap(), v);
        assert_eq!(TestBytes::from_hex("0xdeadbeef").unwrap(), v);
    }
}
