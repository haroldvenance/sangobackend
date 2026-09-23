//! Erreur produite lors de l'application d'une transaction à l'état.

use sango_primitives::NativeAddress;
use sango_state::StateError;
use sango_types::TxKind;
use thiserror::Error;

/// Erreur produite lors de l'application d'une transaction à l'état.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ApplyError {
    /// Le `tx_kind` n'est pas géré par l'applier natif.
    #[error("tx_kind {0:?} is not supported by the native applier")]
    UnsupportedTxKind(TxKind),

    /// `TX_TRANSFER` sans destinataire.
    #[error("TX_TRANSFER requires a recipient")]
    MissingRecipient,

    /// `value + total_fee` déborde `u128`.
    #[error("value + fee overflows u128: value={value}, fee={fee}")]
    FeeOverflow {
        /// Montant transféré.
        value: u128,
        /// Frais totaux.
        fee: u128,
    },

    /// `gas_used * effective_gas_price` déborde `u128`.
    #[error("gas_used * effective_gas_price overflows u128")]
    TotalFeeOverflow,

    /// La somme des `gas_used` d'un bloc déborde `u64`.
    #[error("total_gas_used overflows u64")]
    TotalGasUsedOverflow,

    /// Solde insuffisant au moment de l'application.
    #[error("insufficient balance at apply time: needed {needed}, available {available}")]
    InsufficientBalance {
        /// Montant requis.
        needed: u128,
        /// Solde disponible.
        available: u128,
    },

    /// Un crédit ferait déborder `u128`.
    #[error("balance overflow on credit to {address}")]
    BalanceOverflow {
        /// Adresse créditée.
        address: NativeAddress,
    },

    /// Un `bump_nonce` ferait déborder `u64`.
    #[error("nonce overflow on {address}")]
    NonceOverflow {
        /// Adresse concernée.
        address: NativeAddress,
    },

    /// Nombre de transactions différent du nombre de validations.
    #[error("length mismatch: {txs} txs, {validated} validated")]
    LengthMismatch {
        /// Nombre de transactions.
        txs: usize,
        /// Nombre de validations.
        validated: usize,
    },

    /// `total_burned > initial_supply` : incohérence d'état.
    #[error("current_supply underflow: initial {initial}, burned {burned}")]
    CurrentSupplyUnderflow {
        /// Offre initiale.
        initial: u128,
        /// Cumul brûlé.
        burned: u128,
    },

    /// Erreur d'état sous-jacente.
    #[error("state error: {0}")]
    State(#[from] StateError),

    // --- Staking ------------------------------------------------------------
    /// Un validateur est déjà enregistré à cette adresse.
    #[error("validator already registered: {0}")]
    ValidatorAlreadyExists(NativeAddress),

    /// Aucun validateur à cette adresse.
    #[error("validator not found: {0}")]
    ValidatorNotFound(NativeAddress),

    /// L'émetteur n'est pas un validateur enregistré.
    #[error("sender is not a validator: {0}")]
    NotAValidator(NativeAddress),

    /// Le self-stake restant serait inférieur au minimum après unbond.
    #[error("insufficient self-stake after operation: needed {needed}, would be {would_be}")]
    InsufficientSelfStake {
        /// Minimum requis.
        needed: u128,
        /// Valeur résultante.
        would_be: u128,
    },

    /// Self-stake insuffisant pour l'unbond.
    #[error("insufficient self-stake: needed {needed}, available {available}")]
    InsufficientSelfStakeAvailable {
        /// Montant demandé.
        needed: u128,
        /// Montant disponible.
        available: u128,
    },

    /// Délégation insuffisante pour l'undelegate.
    #[error("insufficient delegation: needed {needed}, available {available}")]
    InsufficientDelegation {
        /// Montant demandé.
        needed: u128,
        /// Montant disponible.
        available: u128,
    },

    /// Commission au-dessus du maximum.
    #[error("commission too high: got {got}, max {max}")]
    CommissionTooHigh {
        /// Valeur reçue (bps).
        got: u32,
        /// Valeur maximale (bps).
        max: u32,
    },

    /// Tentative d'unjail avant expiration.
    #[error("jail period has not expired: until {until}, now {now}")]
    JailNotExpired {
        /// Timestamp Unix de fin de jail.
        until: u64,
        /// Timestamp Unix courant.
        now: u64,
    },

    /// Tentative d'unjail d'un validateur qui n'est pas jailed.
    #[error("validator is not jailed: {0}")]
    NotJailed(NativeAddress),

    /// Le compte n'a pas de clé publique enregistrée et la transaction n'en
    /// déclare pas (bootstrap requis).
    #[error("sender has no registered public key and tx does not provide one")]
    MissingPublicKey,

    /// Auto-délégation interdite en V1.
    #[error("self-delegation is not allowed")]
    SelfDelegation,

    /// Données de commission invalides (longueur incorrecte).
    #[error("invalid commission data")]
    InvalidCommissionData,

    // --- Evidence / slashing ------------------------------------------------
    /// Evidence déjà appliquée.
    #[error("evidence already applied: {0}")]
    EvidenceAlreadyApplied(sango_primitives::Hash32),

    /// Evidence invalide (validation structurelle).
    #[error("invalid evidence: {0}")]
    InvalidEvidence(&'static str),

    /// Validateur en jail mais pas encore expiré.
    #[error("validator already jailed")]
    AlreadyJailed(NativeAddress),
}
