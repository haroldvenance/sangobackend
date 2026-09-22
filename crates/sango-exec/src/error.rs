//! Erreur produite lors de l'application d'une transaction à l'état.

use sango_primitives::NativeAddress;
use sango_state::StateError;
use sango_types::TxKind;
use thiserror::Error;

/// Erreur produite lors de l'application d'une transaction à l'état.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ApplyError {
    /// Le `tx_kind` n'est pas géré par l'applier natif.
    ///
    /// Les `TX_CONTRACT_CALL` et `TX_CONTRACT_CREATE` seront traités par
    /// la couche EVM (à venir).
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

    /// Erreur d'état sous-jacente.
    #[error("state error: {0}")]
    State(#[from] StateError),
}
