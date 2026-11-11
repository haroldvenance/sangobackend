//! Étapes de validation d'une transaction native.
//!
//! Pipeline (Freeze, section 2.8) :
//!
//! ```text
//! decode → structure → chain_id → signature → nonce → balance → gas/fee
//! ```
//!
//! ## Deux points d'entrée
//!
//! - [`validate_transaction`] : validation **à l'application** (bloc).
//!   Exige `tx.nonce == account.nonce`.
//! - [`validate_for_mempool`] : validation **à l'admission mempool**.
//!   Accepte `tx.nonce ∈ [account.nonce, account.nonce + max_gap]`.
//!   Utilisé par `sango-node::rpc_backend` avant tout `pool.add()`.
//!
//! ## Bootstrap de clé publique — RÉSOLU (A1)
//!
//! Un compte est typiquement **crédité d'abord** par un transfert entrant :
//! il existe alors sous forme « fantôme » (`public_key = None`). Pour
//! pouvoir émettre une transaction, il doit **activer** sa clé publique en
//! la déclarant dans sa première transaction (`tx.public_key = Some(pk)`).
//!
//! Règles :
//!
//! - `tx.public_key = None` : le compte doit avoir une clé enregistrée ;
//!   la signature est vérifiée contre la clé d'état.
//! - `tx.public_key = Some(pk)` : `derive_native_address(pk) == tx.sender`
//!   requis ; la signature est vérifiée contre `pk`. Si le compte a déjà
//!   une clé enregistrée, elle doit être **identique** (pas de rotation).
//! - `Some(PublicKey::ZERO)` est rejeté en validation structurelle.

use sango_crypto::derive_native_address;
use sango_primitives::{ChainId32, Hash32, NativeAddress, PublicKey};
use sango_types::{Transaction, TxKind};

use crate::error::TxValidationError;
use crate::fee;

/// Informations sur le compte émetteur, nécessaires à la validation.
///
/// **Découplage volontaire** : ce crate ne dépend pas de `sango-state`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SenderInfo {
    /// Adresse native du compte émetteur.
    pub address: NativeAddress,
    /// Clé publique Ed25519 enregistrée, si elle existe.
    pub public_key: Option<PublicKey>,
    /// Solde disponible en base units.
    pub balance: u128,
    /// Nonce courant du compte.
    pub nonce: u64,
}

impl SenderInfo {
    /// Construit un `SenderInfo` pour un compte actif avec une clé publique
    /// enregistrée.
    #[must_use]
    pub fn from_public_key(public_key: PublicKey, balance: u128, nonce: u64) -> Self {
        let address = derive_native_address(&public_key);
        Self {
            address,
            public_key: Some(public_key),
            balance,
            nonce,
        }
    }

    /// Construit un `SenderInfo` pour un compte « fantôme » (crédité mais
    /// sans clé publique enregistrée).
    #[must_use]
    pub fn ghost(address: NativeAddress, balance: u128, nonce: u64) -> Self {
        Self {
            address,
            public_key: None,
            balance,
            nonce,
        }
    }
}

/// Contexte de validation.
#[derive(Clone, Copy, Debug)]
pub struct ValidationContext<'a> {
    /// Chain ID attendu pour le réseau courant.
    pub expected_chain_id: ChainId32,
    /// Base fee courante (base units par gas).
    pub base_fee: u128,
    /// Informations sur le compte émetteur.
    pub sender: &'a SenderInfo,
}

/// Résultat d'une transaction validée.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedTransaction {
    /// Hash canonique de la transaction.
    pub tx_hash: Hash32,
    /// Adresse native de l'émetteur.
    pub sender: NativeAddress,
    /// Prix effectif par unité de gas.
    pub effective_gas_price: u128,
    /// Frais maximaux (`gas_limit * effective_gas_price`).
    pub max_total_fee: u128,
    /// Montant transféré (base units).
    pub value: u128,
    /// Si `Some(pk)`, la couche d'état **doit** enregistrer `pk` comme clé
    /// publique du compte `sender` lors de l'application de la transaction.
    pub bootstrap_public_key: Option<PublicKey>,
}

/// Valide une transaction **à l'application** (bloc).
///
/// Exige `tx.nonce == sender.nonce`. Pour l'admission mempool, utiliser
/// [`validate_for_mempool`] qui accepte une fenêtre de nonces.
pub fn validate_transaction(
    tx: &Transaction,
    ctx: &ValidationContext<'_>,
) -> Result<ValidatedTransaction, TxValidationError> {
    validate_structure(tx)?;
    validate_chain_id(tx, ctx.expected_chain_id)?;
    validate_signature(tx, ctx.sender)?;
    validate_nonce(tx, ctx.sender.nonce)?;
    let price = validate_fee(tx, ctx.base_fee)?;
    let max_total = fee::total_fee(tx.gas_limit, price).ok_or(TxValidationError::FeeOverflow)?;
    validate_balance(tx, ctx.sender.balance, max_total)?;

    let bootstrap_public_key = match (tx.public_key, ctx.sender.public_key) {
        (Some(pk), None) => Some(pk),
        _ => None,
    };

    Ok(ValidatedTransaction {
        tx_hash: tx.hash(),
        sender: tx.sender,
        effective_gas_price: price,
        max_total_fee: max_total,
        value: tx.value.base_units(),
        bootstrap_public_key,
    })
}

/// Valide une transaction **à l'admission mempool**.
///
/// Différences avec [`validate_transaction`] :
///
/// - **Nonce en fenêtre** : accepte `tx.nonce ∈ [sender.nonce,
///   sender.nonce + max_nonce_gap]` au lieu de `== sender.nonce`.
///   Cela permet de mettre en file des transactions séquentielles
///   (pipeline mempool).
///
/// Toutes les autres validations sont identiques (structure, chain_id,
/// signature, fee, balance, bootstrap).
///
/// ## Rôle vis-à-vis du DoS
///
/// Cette fonction est le **seul rempart** contre un mempool griefé par
/// des transactions forgées (`tx.sender` non authentique). Le
/// `pool.add()` reçoit un [`ValidatedTransaction`] qui prouve que la
/// signature a été vérifiée.
pub fn validate_for_mempool(
    tx: &Transaction,
    ctx: &ValidationContext<'_>,
    max_nonce_gap: u64,
) -> Result<ValidatedTransaction, TxValidationError> {
    // (1) Structure : kind/data/montants/commission.
    validate_structure(tx)?;

    // (2) Chain ID : anti-replay cross-network.
    validate_chain_id(tx, ctx.expected_chain_id)?;

    // (3) Signature : vérifie cryptographiquement la clé Ed25519.
    validate_signature(tx, ctx.sender)?;

    // (4) Nonce en FENÊTRE (différence vs validate_transaction).
    let min = ctx.sender.nonce;
    let max = ctx.sender.nonce.saturating_add(max_nonce_gap);
    if tx.nonce < min {
        return Err(TxValidationError::NonceTooLow {
            min,
            got: tx.nonce,
        });
    }
    if tx.nonce > max {
        return Err(TxValidationError::NonceTooHigh {
            max,
            got: tx.nonce,
        });
    }

    // (5) Fee : max_fee >= base_fee, priority <= max.
    let price = validate_fee(tx, ctx.base_fee)?;

    // (6) Balance : value + max_fee <= balance.
    let max_total = fee::total_fee(tx.gas_limit, price).ok_or(TxValidationError::FeeOverflow)?;
    validate_balance(tx, ctx.sender.balance, max_total)?;

    // (7) Bootstrap : identique à validate_transaction.
    let bootstrap_public_key = match (tx.public_key, ctx.sender.public_key) {
        (Some(pk), None) => Some(pk),
        _ => None,
    };

    Ok(ValidatedTransaction {
        tx_hash: tx.hash(),
        sender: tx.sender,
        effective_gas_price: price,
        max_total_fee: max_total,
        value: tx.value.base_units(),
        bootstrap_public_key,
    })
}

/// Valide la structure de la transaction.
pub fn validate_structure(tx: &Transaction) -> Result<(), TxValidationError> {
    if tx.version != 1 {
        return Err(TxValidationError::UnsupportedVersion(tx.version));
    }
    if tx.gas_limit == 0 {
        return Err(TxValidationError::ZeroGasLimit);
    }
    if tx.priority_fee > tx.max_fee {
        return Err(TxValidationError::PriorityFeeExceedsMaxFee {
            priority_fee: tx.priority_fee,
            max_fee: tx.max_fee,
        });
    }
    if let Some(pk) = &tx.public_key {
        if pk.is_zero() {
            return Err(TxValidationError::InvalidStructure(
                "public_key must not be PublicKey::ZERO",
            ));
        }
    }
    match tx.tx_kind {
        TxKind::Transfer => {
            if tx.recipient.is_none() {
                return Err(TxValidationError::InvalidStructure(
                    "TX_TRANSFER requires a recipient",
                ));
            }
            if !tx.data.is_empty() {
                return Err(TxValidationError::InvalidStructure(
                    "TX_TRANSFER must have empty data",
                ));
            }
        }
        TxKind::ContractCall => {
            if tx.recipient.is_none() {
                return Err(TxValidationError::InvalidStructure(
                    "TX_CONTRACT_CALL requires a recipient",
                ));
            }
        }
        TxKind::ContractCreate => {
            if tx.recipient.is_some() {
                return Err(TxValidationError::InvalidStructure(
                    "TX_CONTRACT_CREATE must have no recipient",
                ));
            }
        }
        TxKind::Bond => {
            if tx.recipient.is_some() {
                return Err(TxValidationError::InvalidStructure(
                    "TX_BOND must have no recipient",
                ));
            }
            if !tx.data.is_empty() {
                return Err(TxValidationError::InvalidStructure(
                    "TX_BOND must have empty data",
                ));
            }
            if tx.value.is_zero() {
                return Err(TxValidationError::InvalidStructure(
                    "TX_BOND requires a positive amount",
                ));
            }
        }
        TxKind::Unbond => {
            if tx.recipient.is_some() {
                return Err(TxValidationError::InvalidStructure(
                    "TX_UNBOND must have no recipient",
                ));
            }
            if !tx.data.is_empty() {
                return Err(TxValidationError::InvalidStructure(
                    "TX_UNBOND must have empty data",
                ));
            }
            if tx.value.is_zero() {
                return Err(TxValidationError::InvalidStructure(
                    "TX_UNBOND requires a positive amount",
                ));
            }
        }
        TxKind::Delegate => {
            if tx.recipient.is_none() {
                return Err(TxValidationError::InvalidStructure(
                    "TX_DELEGATE requires a validator recipient",
                ));
            }
            if !tx.data.is_empty() {
                return Err(TxValidationError::InvalidStructure(
                    "TX_DELEGATE must have empty data",
                ));
            }
            if tx.value.is_zero() {
                return Err(TxValidationError::InvalidStructure(
                    "TX_DELEGATE requires a positive amount",
                ));
            }
        }
        TxKind::Undelegate => {
            if tx.recipient.is_none() {
                return Err(TxValidationError::InvalidStructure(
                    "TX_UNDELEGATE requires a validator recipient",
                ));
            }
            if !tx.data.is_empty() {
                return Err(TxValidationError::InvalidStructure(
                    "TX_UNDELEGATE must have empty data",
                ));
            }
            if tx.value.is_zero() {
                return Err(TxValidationError::InvalidStructure(
                    "TX_UNDELEGATE requires a positive amount",
                ));
            }
        }
        TxKind::ClaimRewards => {
            if tx.recipient.is_none() {
                return Err(TxValidationError::InvalidStructure(
                    "TX_CLAIM_REWARDS requires a validator recipient",
                ));
            }
            if !tx.data.is_empty() {
                return Err(TxValidationError::InvalidStructure(
                    "TX_CLAIM_REWARDS must have empty data",
                ));
            }
            if !tx.value.is_zero() {
                return Err(TxValidationError::InvalidStructure(
                    "TX_CLAIM_REWARDS must have value 0",
                ));
            }
        }
        TxKind::RegisterValidator => {
            if tx.recipient.is_some() {
                return Err(TxValidationError::InvalidStructure(
                    "TX_REGISTER_VALIDATOR must have no recipient",
                ));
            }
            if tx.data.len() != 4 {
                return Err(TxValidationError::InvalidStructure(
                    "TX_REGISTER_VALIDATOR data must be 4 bytes",
                ));
            }
            let commission_bps =
                u32::from_be_bytes([tx.data[0], tx.data[1], tx.data[2], tx.data[3]]);
            if commission_bps > sango_types::staking_params::MAX_COMMISSION_BPS {
                return Err(TxValidationError::InvalidStructure(
                    "commission_bps exceeds maximum",
                ));
            }
            if tx.value < sango_types::staking_params::min_self_stake() {
                return Err(TxValidationError::InvalidStructure(
                    "TX_REGISTER_VALIDATOR below minimum self-stake",
                ));
            }
        }
        TxKind::UpdateCommission => {
            if tx.recipient.is_some() {
                return Err(TxValidationError::InvalidStructure(
                    "TX_UPDATE_COMMISSION must have no recipient",
                ));
            }
            if tx.data.len() != 4 {
                return Err(TxValidationError::InvalidStructure(
                    "TX_UPDATE_COMMISSION data must be 4 bytes",
                ));
            }
            let new_bps =
                u32::from_be_bytes([tx.data[0], tx.data[1], tx.data[2], tx.data[3]]);
            if new_bps > sango_types::staking_params::MAX_COMMISSION_BPS {
                return Err(TxValidationError::InvalidStructure(
                    "new commission_bps exceeds maximum",
                ));
            }
            if !tx.value.is_zero() {
                return Err(TxValidationError::InvalidStructure(
                    "TX_UPDATE_COMMISSION must have value 0",
                ));
            }
        }
        TxKind::Unjail => {
            if tx.recipient.is_some() {
                return Err(TxValidationError::InvalidStructure(
                    "TX_UNJAIL must have no recipient",
                ));
            }
            if !tx.data.is_empty() {
                return Err(TxValidationError::InvalidStructure(
                    "TX_UNJAIL must have empty data",
                ));
            }
            if !tx.value.is_zero() {
                return Err(TxValidationError::InvalidStructure(
                    "TX_UNJAIL must have value 0",
                ));
            }
        }
    }
    Ok(())
}

/// Vérifie que le `chain_id` de la transaction correspond au réseau.
pub fn validate_chain_id(tx: &Transaction, expected: ChainId32) -> Result<(), TxValidationError> {
    if tx.chain_id != expected {
        return Err(TxValidationError::ChainIdMismatch {
            expected,
            actual: tx.chain_id,
        });
    }
    Ok(())
}

/// Vérifie la signature et la cohérence de [`SenderInfo`].
pub fn validate_signature(tx: &Transaction, sender: &SenderInfo) -> Result<(), TxValidationError> {
    if sender.address != tx.sender {
        return Err(TxValidationError::SenderInfoAddressMismatch);
    }

    let effective_pubkey = match tx.public_key {
        Some(declared) => {
            if derive_native_address(&declared) != tx.sender {
                return Err(TxValidationError::PublicKeyDoesNotMatchSender);
            }
            if let Some(existing) = sender.public_key {
                if existing != declared {
                    return Err(TxValidationError::PublicKeyAlreadySet);
                }
            }
            declared
        }
        None => {
            let existing = sender
                .public_key
                .ok_or(TxValidationError::PublicKeyNotRegistered)?;
            if derive_native_address(&existing) != tx.sender {
                return Err(TxValidationError::PublicKeyDoesNotMatchSender);
            }
            existing
        }
    };

    tx.verify(&effective_pubkey)
        .map_err(|_| TxValidationError::InvalidSignature)?;

    Ok(())
}

/// Vérifie que le nonce de la transaction correspond au nonce attendu
/// (validation à l'application).
pub fn validate_nonce(tx: &Transaction, expected_nonce: u64) -> Result<(), TxValidationError> {
    if tx.nonce != expected_nonce {
        return Err(TxValidationError::NonceMismatch {
            expected: expected_nonce,
            actual: tx.nonce,
        });
    }
    Ok(())
}

/// Vérifie les frais et retourne le prix effectif.
pub fn validate_fee(tx: &Transaction, base_fee: u128) -> Result<u128, TxValidationError> {
    if tx.max_fee < base_fee {
        return Err(TxValidationError::MaxFeeBelowBaseFee {
            max_fee: tx.max_fee,
            base_fee,
        });
    }
    let cap = base_fee
        .checked_add(tx.priority_fee)
        .ok_or(TxValidationError::FeeOverflow)?;
    Ok(tx.max_fee.min(cap))
}

/// Vérifie que le solde disponible couvre `value + max_total_fee`.
pub fn validate_balance(
    tx: &Transaction,
    available: u128,
    max_total_fee: u128,
) -> Result<(), TxValidationError> {
    let needed = tx
        .value
        .base_units()
        .checked_add(max_total_fee)
        .ok_or(TxValidationError::FeeOverflow)?;
    if needed > available {
        return Err(TxValidationError::InsufficientBalance { needed, available });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sango_crypto::NativeKeypair;
    use sango_primitives::{Amount, Signature};

    fn chain() -> ChainId32 {
        ChainId32::from_bytes([0x11; 32])
    }

    fn signed_transfer(
        keypair: &NativeKeypair,
        nonce: u64,
        value: u128,
        balance: u128,
    ) -> (Transaction, SenderInfo) {
        let pk = keypair.public_key();
        let sender = derive_native_address(&pk);
        let mut tx = Transaction {
            version: 1,
            chain_id: chain(),
            nonce,
            sender,
            public_key: None,
            gas_limit: 21_000,
            max_fee: 20,
            priority_fee: 2,
            value: Amount::from_base_units(value),
            tx_kind: TxKind::Transfer,
            recipient: Some(NativeAddress::from_bytes([0xbb; 20])),
            data: Vec::new(),
            signature: Signature::ZERO,
        };
        tx = tx.sign(keypair);
        (
            tx,
            SenderInfo {
                address: sender,
                public_key: Some(pk),
                balance,
                nonce,
            },
        )
    }

    fn signed_bootstrap_transfer(
        keypair: &NativeKeypair,
        nonce: u64,
        value: u128,
        balance: u128,
    ) -> (Transaction, SenderInfo) {
        let pk = keypair.public_key();
        let sender = derive_native_address(&pk);
        let mut tx = Transaction {
            version: 1,
            chain_id: chain(),
            nonce,
            sender,
            public_key: Some(pk),
            gas_limit: 21_000,
            max_fee: 20,
            priority_fee: 2,
            value: Amount::from_base_units(value),
            tx_kind: TxKind::Transfer,
            recipient: Some(NativeAddress::from_bytes([0xbb; 20])),
            data: Vec::new(),
            signature: Signature::ZERO,
        };
        tx = tx.sign(keypair);
        (
            tx,
            SenderInfo {
                address: sender,
                public_key: None,
                balance,
                nonce,
            },
        )
    }

    #[test]
    fn sender_info_from_public_key() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let pk = kp.public_key();
        let info = SenderInfo::from_public_key(pk, 100, 0);
        assert_eq!(info.address, derive_native_address(&pk));
        assert_eq!(info.public_key, Some(pk));
    }

    #[test]
    fn sender_info_ghost() {
        let a = NativeAddress::from_bytes([0xaa; 20]);
        let info = SenderInfo::ghost(a, 500, 3);
        assert_eq!(info.public_key, None);
    }

    #[test]
    fn structure_ok_transfer() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (tx, _) = signed_transfer(&kp, 0, 100, 1_000_000);
        assert!(validate_structure(&tx).is_ok());
    }

    #[test]
    fn structure_rejects_wrong_version() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (mut tx, _) = signed_transfer(&kp, 0, 100, 1_000_000);
        tx.version = 2;
        assert_eq!(
            validate_structure(&tx),
            Err(TxValidationError::UnsupportedVersion(2))
        );
    }

    #[test]
    fn structure_rejects_zero_gas() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (mut tx, _) = signed_transfer(&kp, 0, 100, 1_000_000);
        tx.gas_limit = 0;
        assert_eq!(
            validate_structure(&tx),
            Err(TxValidationError::ZeroGasLimit)
        );
    }

    #[test]
    fn structure_rejects_priority_above_max() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (mut tx, _) = signed_transfer(&kp, 0, 100, 1_000_000);
        tx.priority_fee = tx.max_fee + 1;
        assert!(matches!(
            validate_structure(&tx),
            Err(TxValidationError::PriorityFeeExceedsMaxFee { .. })
        ));
    }

    #[test]
    fn structure_rejects_transfer_without_recipient() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (mut tx, _) = signed_transfer(&kp, 0, 100, 1_000_000);
        tx.recipient = None;
        assert!(matches!(
            validate_structure(&tx),
            Err(TxValidationError::InvalidStructure(_))
        ));
    }

    #[test]
    fn structure_rejects_transfer_with_data() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (mut tx, _) = signed_transfer(&kp, 0, 100, 1_000_000);
        tx.data = vec![1, 2, 3];
        assert!(matches!(
            validate_structure(&tx),
            Err(TxValidationError::InvalidStructure(_))
        ));
    }

    #[test]
    fn structure_contract_create_no_recipient_ok() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (mut tx, _) = signed_transfer(&kp, 0, 100, 1_000_000);
        tx.tx_kind = TxKind::ContractCreate;
        tx.recipient = None;
        tx.data = vec![0x60, 0x80];
        assert!(validate_structure(&tx).is_ok());
    }

    #[test]
    fn structure_contract_create_with_recipient_fails() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (mut tx, _) = signed_transfer(&kp, 0, 100, 1_000_000);
        tx.tx_kind = TxKind::ContractCreate;
        assert!(matches!(
            validate_structure(&tx),
            Err(TxValidationError::InvalidStructure(_))
        ));
    }

    #[test]
    fn structure_rejects_zero_declared_public_key() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (mut tx, _) = signed_transfer(&kp, 0, 100, 1_000_000);
        tx.public_key = Some(PublicKey::ZERO);
        assert!(matches!(
            validate_structure(&tx),
            Err(TxValidationError::InvalidStructure(_))
        ));
    }

    #[test]
    fn chain_id_ok() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (tx, _) = signed_transfer(&kp, 0, 100, 1_000_000);
        assert!(validate_chain_id(&tx, chain()).is_ok());
    }

    #[test]
    fn chain_id_mismatch() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (tx, _) = signed_transfer(&kp, 0, 100, 1_000_000);
        let other = ChainId32::from_bytes([0x99; 32]);
        assert!(matches!(
            validate_chain_id(&tx, other),
            Err(TxValidationError::ChainIdMismatch { .. })
        ));
    }

    #[test]
    fn signature_ok_normal_path() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (tx, info) = signed_transfer(&kp, 0, 100, 1_000_000);
        assert!(validate_signature(&tx, &info).is_ok());
    }

    #[test]
    fn signature_rejects_sender_info_address_mismatch() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (tx, mut info) = signed_transfer(&kp, 0, 100, 1_000_000);
        info.address = NativeAddress::from_bytes([0xff; 20]);
        assert_eq!(
            validate_signature(&tx, &info),
            Err(TxValidationError::SenderInfoAddressMismatch)
        );
    }

    #[test]
    fn signature_rejects_pubkey_not_deriving_to_sender() {
        let kp1 = NativeKeypair::from_seed([0x42; 32]);
        let kp2 = NativeKeypair::from_seed([0x43; 32]);
        let (tx, mut info) = signed_transfer(&kp1, 0, 100, 1_000_000);
        info.public_key = Some(kp2.public_key());
        assert_eq!(
            validate_signature(&tx, &info),
            Err(TxValidationError::PublicKeyDoesNotMatchSender)
        );
    }

    #[test]
    fn signature_rejects_tampered_tx() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (mut tx, info) = signed_transfer(&kp, 0, 100, 1_000_000);
        tx.value = Amount::from_base_units(101);
        assert_eq!(
            validate_signature(&tx, &info),
            Err(TxValidationError::InvalidSignature)
        );
    }

    #[test]
    fn signature_rejects_unregistered_public_key_no_declaration() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (tx, mut info) = signed_transfer(&kp, 0, 100, 1_000_000);
        info.public_key = None;
        assert_eq!(
            validate_signature(&tx, &info),
            Err(TxValidationError::PublicKeyNotRegistered)
        );
    }

    #[test]
    fn bootstrap_ok() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (tx, info) = signed_bootstrap_transfer(&kp, 0, 100, 1_000_000);
        assert!(validate_signature(&tx, &info).is_ok());
    }

    #[test]
    fn bootstrap_rejects_declared_pubkey_mismatch() {
        let kp1 = NativeKeypair::from_seed([0x42; 32]);
        let kp2 = NativeKeypair::from_seed([0x43; 32]);
        let (mut tx, info) = signed_bootstrap_transfer(&kp1, 0, 100, 1_000_000);
        tx.public_key = Some(kp2.public_key());
        assert_eq!(
            validate_signature(&tx, &info),
            Err(TxValidationError::PublicKeyDoesNotMatchSender)
        );
    }

    #[test]
    fn bootstrap_idempotent_when_pubkey_already_set_same() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (mut tx, info) = signed_transfer(&kp, 0, 100, 1_000_000);
        tx.public_key = Some(kp.public_key());
        tx = tx.sign(&kp);
        assert!(validate_signature(&tx, &info).is_ok());
    }

    #[test]
    fn bootstrap_rejects_key_rotation() {
        let kp1 = NativeKeypair::from_seed([0x42; 32]);
        let kp2 = NativeKeypair::from_seed([0x43; 32]);
        let (tx, mut info) = signed_bootstrap_transfer(&kp1, 0, 100, 1_000_000);
        info.public_key = Some(kp2.public_key());
        assert_eq!(
            validate_signature(&tx, &info),
            Err(TxValidationError::PublicKeyAlreadySet)
        );
    }

    #[test]
    fn nonce_ok() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (tx, _) = signed_transfer(&kp, 5, 100, 1_000_000);
        assert!(validate_nonce(&tx, 5).is_ok());
    }

    #[test]
    fn nonce_mismatch() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (tx, _) = signed_transfer(&kp, 5, 100, 1_000_000);
        assert_eq!(
            validate_nonce(&tx, 6),
            Err(TxValidationError::NonceMismatch {
                expected: 6,
                actual: 5
            })
        );
    }

    #[test]
    fn fee_ok() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (tx, _) = signed_transfer(&kp, 0, 100, 1_000_000);
        assert_eq!(validate_fee(&tx, 10).unwrap(), 12);
    }

    #[test]
    fn fee_max_below_base() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (mut tx, _) = signed_transfer(&kp, 0, 100, 1_000_000);
        tx.max_fee = 5;
        tx.priority_fee = 1;
        assert!(matches!(
            validate_fee(&tx, 10),
            Err(TxValidationError::MaxFeeBelowBaseFee { .. })
        ));
    }

    #[test]
    fn balance_ok() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (tx, _) = signed_transfer(&kp, 0, 100, 1_000_000);
        assert!(validate_balance(&tx, 1_000_000, 500_000).is_ok());
    }

    #[test]
    fn balance_insufficient() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (tx, _) = signed_transfer(&kp, 0, 100, 1_000_000);
        assert!(matches!(
            validate_balance(&tx, 100, 500_000),
            Err(TxValidationError::InsufficientBalance { .. })
        ));
    }

    #[test]
    fn full_pipeline_ok_normal() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (tx, info) = signed_transfer(&kp, 0, 100, 1_000_000);
        let ctx = ValidationContext {
            expected_chain_id: chain(),
            base_fee: 10,
            sender: &info,
        };
        let v = validate_transaction(&tx, &ctx).unwrap();
        assert_eq!(v.effective_gas_price, 12);
        assert_eq!(v.max_total_fee, 21_000 * 12);
        assert_eq!(v.bootstrap_public_key, None);
    }

    #[test]
    fn full_pipeline_ok_bootstrap() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let pk = kp.public_key();
        let (tx, info) = signed_bootstrap_transfer(&kp, 0, 100, 1_000_000);
        let ctx = ValidationContext {
            expected_chain_id: chain(),
            base_fee: 10,
            sender: &info,
        };
        let v = validate_transaction(&tx, &ctx).unwrap();
        assert_eq!(v.bootstrap_public_key, Some(pk));
    }

    #[test]
    fn full_pipeline_first_error_wins() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (mut tx, info) = signed_transfer(&kp, 0, 100, 1_000_000);
        tx.version = 99;
        let ctx = ValidationContext {
            expected_chain_id: chain(),
            base_fee: 10,
            sender: &info,
        };
        assert_eq!(
            validate_transaction(&tx, &ctx).unwrap_err(),
            TxValidationError::UnsupportedVersion(99)
        );
    }

    #[test]
    fn full_pipeline_does_not_mutate_tx() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (tx, info) = signed_transfer(&kp, 0, 100, 1_000_000);
        let original = tx.clone();
        let ctx = ValidationContext {
            expected_chain_id: chain(),
            base_fee: 10,
            sender: &info,
        };
        let _ = validate_transaction(&tx, &ctx);
        assert_eq!(tx, original);
    }

    // === validate_for_mempool tests ===

    #[test]
    fn mempool_accepts_nonce_current() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (tx, info) = signed_transfer(&kp, 5, 100, 1_000_000);
        let ctx = ValidationContext {
            expected_chain_id: chain(),
            base_fee: 10,
            sender: &info,
        };
        assert!(validate_for_mempool(&tx, &ctx, 64).is_ok());
    }

    #[test]
    fn mempool_accepts_nonce_ahead_within_gap() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (tx, info) = signed_transfer(&kp, 5 + 32, 100, 1_000_000);
        let ctx = ValidationContext {
            expected_chain_id: chain(),
            base_fee: 10,
            sender: &info,
        };
        assert!(validate_for_mempool(&tx, &ctx, 64).is_ok());
    }

    #[test]
    fn mempool_accepts_nonce_at_gap_boundary() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (tx, info) = signed_transfer(&kp, 5 + 64, 100, 1_000_000);
        let ctx = ValidationContext {
            expected_chain_id: chain(),
            base_fee: 10,
            sender: &info,
        };
        assert!(validate_for_mempool(&tx, &ctx, 64).is_ok());
    }

    // FIX : le helper `signed_transfer(&kp, 3, ...)` initialisait à la
    // fois `tx.nonce = 3` ET `info.nonce = 3` — la fenêtre ne pouvait donc
    // pas détecter un décalage. On surcharge `info.nonce` après le helper
    // pour simuler un état où le compte est à `nonce = 5` alors que la tx
    // signée utilise `nonce = 3`. La signature reste valide car Ed25519
    // couvre `tx` uniquement (`tx.verify()` ne lit pas `info`).
    #[test]
    fn mempool_rejects_nonce_below_min() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (tx, mut info) = signed_transfer(&kp, 3, 100, 1_000_000);
        info.nonce = 5; // état simulé à nonce=5
        let ctx = ValidationContext {
            expected_chain_id: chain(),
            base_fee: 10,
            sender: &info,
        };
        assert!(matches!(
            validate_for_mempool(&tx, &ctx, 64),
            Err(TxValidationError::NonceTooLow { min: 5, got: 3 })
        ));
    }

    // FIX : même cause — `signed_transfer(&kp, 5 + 65, ...)` alignait
    // `tx.nonce` et `info.nonce`. On fixe `info.nonce = 5` pour simuler
    // un état à nonce=5, la tx signée à nonce=70, gap=64 → 70 > 69.
    #[test]
    fn mempool_rejects_nonce_above_gap() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (tx, mut info) = signed_transfer(&kp, 70, 100, 1_000_000);
        info.nonce = 5; // état simulé à nonce=5, gap=64 → max=69
        let ctx = ValidationContext {
            expected_chain_id: chain(),
            base_fee: 10,
            sender: &info,
        };
        assert!(matches!(
            validate_for_mempool(&tx, &ctx, 64),
            Err(TxValidationError::NonceTooHigh { .. })
        ));
    }

    #[test]
    fn mempool_rejects_wrong_chain_id() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (tx, info) = signed_transfer(&kp, 5, 100, 1_000_000);
        let ctx = ValidationContext {
            expected_chain_id: ChainId32::from_bytes([0x99; 32]),
            base_fee: 10,
            sender: &info,
        };
        assert!(matches!(
            validate_for_mempool(&tx, &ctx, 64),
            Err(TxValidationError::ChainIdMismatch { .. })
        ));
    }

    #[test]
    fn mempool_rejects_low_balance() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (tx, info) = signed_transfer(&kp, 5, 100, 200);
        let ctx = ValidationContext {
            expected_chain_id: chain(),
            base_fee: 10,
            sender: &info,
        };
        assert!(matches!(
            validate_for_mempool(&tx, &ctx, 64),
            Err(TxValidationError::InsufficientBalance { .. })
        ));
    }

    #[test]
    fn mempool_rejects_priority_above_max_fee() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (mut tx, info) = signed_transfer(&kp, 5, 100, 1_000_000);
        tx.priority_fee = tx.max_fee + 100;
        tx = tx.sign(&kp);
        let ctx = ValidationContext {
            expected_chain_id: chain(),
            base_fee: 10,
            sender: &info,
        };
        assert!(matches!(
            validate_for_mempool(&tx, &ctx, 64),
            Err(TxValidationError::PriorityFeeExceedsMaxFee { .. })
        ));
    }
}