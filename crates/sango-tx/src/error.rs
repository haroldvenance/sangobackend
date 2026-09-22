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

    /// La clé publique (déclarée dans la tx ou enregistrée dans l'état) ne
    /// dérive pas vers `tx.sender`.
    #[error("public key does not derive to tx.sender")]
    PublicKeyDoesNotMatchSender,

    /// Le compte émetteur n'a pas de clé publique enregistrée
    /// (`SenderInfo.public_key == None`) et la transaction n'en déclare
    /// pas non plus (`tx.public_key == None`).
    ///
    /// Le compte doit soit être créé par Genesis, soit avoir déjà été
    /// activé via une transaction déclarant sa clé publique.
    #[error("sender has no registered public key")]
    PublicKeyNotRegistered,

    /// La transaction déclare une clé publique différente de celle déjà
    /// enregistrée pour ce compte. La rotation de clé n'est **pas**
    /// autorisée en V1.
    #[error("public key already registered (rotation not allowed)")]
    PublicKeyAlreadySet,

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
