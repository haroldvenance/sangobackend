//! Erreurs de validation de transaction.

use sango_primitives::ChainId32;
use thiserror::Error;

/// Erreur produite par une étape de validation de transaction native.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TxValidationError {
    /// Version de transaction non supportée.
    #[error("unsupported transaction version: {0}")]
    UnsupportedVersion(u32),

    /// Le `chain_id` de la transaction ne correspond pas au réseau.
    #[error("chain id mismatch")]
    ChainIdMismatch {
        /// Chain ID attendu.
        expected: ChainId32,
        /// Chain ID reçu.
        actual: ChainId32,
    },

    /// Violation d'une règle structurelle (ex. `TX_TRANSFER` sans recipient).
    #[error("invalid structure: {0}")]
    InvalidStructure(&'static str),

    /// L'adresse `sender` déclarée dans `SenderInfo` ne correspond pas au
    /// champ `sender` de la transaction.
    #[error("SenderInfo.address does not match tx.sender")]
    SenderInfoAddressMismatch,

    /// L'adresse dérivée de `SenderInfo.public_key` ne correspond pas au
    /// champ `sender` de la transaction.
    #[error("public key does not derive to tx.sender")]
    PublicKeyDoesNotMatchSender,

    /// Le compte émetteur n'a pas de clé publique enregistrée
    /// (`PublicKey::ZERO`). Voir la documentation de `sango-tx` sur le
    /// bootstrap.
    #[error("sender has no registered public key")]
    PublicKeyNotRegistered,

    /// Vérification de signature échouée.
    #[error("signature verification failed")]
    InvalidSignature,

    /// Nonce incorrect.
    #[error("nonce mismatch: expected {expected}, got {actual}")]
    NonceMismatch {
        /// Nonce attendu.
        expected: u64,
        /// Nonce reçu.
        actual: u64,
    },

    /// Solde insuffisant pour couvrir `value + gas_limit * effective_gas_price`.
    #[error("insufficient balance: needed {needed}, available {available}")]
    InsufficientBalance {
        /// Montant total requis (base units).
        needed: u128,
        /// Solde disponible (base units).
        available: u128,
    },

    /// `max_fee` inférieur à la base fee courante.
    #[error("max_fee ({max_fee}) below base_fee ({base_fee})")]
    MaxFeeBelowBaseFee {
        /// `max_fee` de la transaction.
        max_fee: u128,
        /// Base fee courante.
        base_fee: u128,
    },

    /// `priority_fee` supérieur à `max_fee`.
    #[error("priority_fee ({priority_fee}) exceeds max_fee ({max_fee})")]
    PriorityFeeExceedsMaxFee {
        /// `priority_fee` de la transaction.
        priority_fee: u128,
        /// `max_fee` de la transaction.
        max_fee: u128,
    },

    /// `gas_limit` nul.
    #[error("gas_limit is zero")]
    ZeroGasLimit,

    /// Débordement arithmétique dans le calcul des frais.
    #[error("overflow in fee computation")]
    FeeOverflow,
}
