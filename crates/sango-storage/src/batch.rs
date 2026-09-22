//! Batch d'écritures atomiques.

use crate::column::Column;

/// Batch d'écritures atomiques.
///
/// Utilisé pour appliquer un bloc de manière atomique : blocs, headers,
/// transactions, receipts, changements d'état, mises à jour des validateurs,
/// etc. sont tous commités ensemble ou pas du tout.
///
/// Les changements ne sont visibles qu'après [`crate::Storage::write_batch`].
pub struct Batch {
    ops: Vec<Operation>,
}

pub(crate) enum Operation {
    Put {
        column: Column,
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Delete {
        column: Column,
        key: Vec<u8>,
    },
}

impl Batch {
    /// Crée un batch vide.
    #[must_use]
    pub fn new() -> Self {
        Self { ops: Vec::new() }
    }

    /// Nombre d'opérations dans le batch.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// Vrai si le batch est vide.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Ajoute une écriture.
    pub fn put(&mut self, column: Column, key: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) {
        self.ops.push(Operation::Put {
            column,
            key: key.into(),
            value: value.into(),
        });
    }

    /// Ajoute une suppression.
    pub fn delete(&mut self, column: Column, key: impl Into<Vec<u8>>) {
        self.ops.push(Operation::Delete {
            column,
            key: key.into(),
        });
    }

    /// Consomme le batch et retourne les opérations.
    pub(crate) fn into_ops(self) -> Vec<Operation> {
        self.ops
    }
}

impl Default for Batch {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Batch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Batch")
            .field("ops", &self.ops.len())
            .finish()
    }
}
