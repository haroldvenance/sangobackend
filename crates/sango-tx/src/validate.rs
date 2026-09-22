//! Étapes de validation d'une transaction native.
//!
//! Pipeline (Freeze, section 2.8) :
//!
//! ```text
//! decode → structure → chain_id → signature → nonce → balance → gas/fee
//! ```
//!
//! Chaque étape est exposée comme fonction indépendante.
//!
//! ## Source de la clé publique — À SPÉCIFIER
//!
//! **Statut : OUVERT.** Le Freeze V1 ne définit pas encore comment un nœud
//! obtient la clé publique d'un compte natif. Options envisagées :
//!
//! - **A1** — la première transaction d'un compte fournit sa clé publique
//!   (champ optionnel `public_key` dans `Transaction`) ; le compte est créé
//!   implicitement si `derive(public_key) == tx.sender` et la signature est
//!   valide.
//! - **A2** — tous les comptes sont précréés par Genesis ou opération
//!   protocolaire.
//! - **A3** — la clé publique est incluse dans **toutes** les transactions.
//!
//! Recommandation : **A1**.
//!
//! En attendant, `sango-tx` utilise [`SenderInfo`] fourni par l'appelant
//! (mempool, block builder, RPC). Cela permet :
//!
//! - de tester la validation sans dépendre de `sango-state` ;
//! - de changer la source de la clé publique plus tard sans impacter le
//!   pipeline de validation.

use sango_crypto::derive_native_address;
use sango_primitives::{ChainId32, Hash32, NativeAddress, PublicKey};
use sango_types::{Transaction, TxKind};

use crate::error::TxValidationError;
use crate::fee;

/// Informations sur le compte émetteur, nécessaires à la validation.
///
/// **Découplage volontaire** : ce crate ne dépend pas de `sango-state`. Les
/// informations sont fournies par l'appelant.
///
/// `address` et `public_key` doivent être cohérents :
/// `derive_native_address(&public_key) == address`. Cette cohérence est
/// vérifiée lors de [`validate_signature`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SenderInfo {
    /// Adresse native du compte émetteur.
    pub address: NativeAddress,
    /// Clé publique Ed25519 du compte émetteur.
    pub public_key: PublicKey,
    /// Solde disponible en base units.
    pub balance: u128,
    /// Nonce courant du compte.
    pub nonce: u64,
}

impl SenderInfo {
    /// Construit un `SenderInfo` à partir d'une clé publique et d'un état.
    ///
    /// L'adresse est dérivée automatiquement — impossible de fournir une
    /// adresse incohérente.
    #[must_use]
    pub fn from_public_key(public_key: PublicKey, balance: u128, nonce: u64) -> Self {
        let address = derive_native_address(&public_key);
        Self {
            address,
            public_key,
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
}

/// Valide une transaction contre un contexte de validation.
///
/// Enchaîne les étapes dans l'ordre canonique. Retourne la première erreur
/// rencontrée.
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

    Ok(ValidatedTransaction {
        tx_hash: tx.hash(),
        sender: tx.sender,
        effective_gas_price: price,
        max_total_fee: max_total,
        value: tx.value.base_units(),
    })
}

/// Valide la structure de la transaction en fonction de son `tx_kind`.
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
///
/// Trois contrôles, dans cet ordre :
///
/// 1. `sender.address == tx.sender` — le `SenderInfo` fourni par l'appelant
///    correspond bien à la transaction ;
/// 2. `derive_native_address(&sender.public_key) == tx.sender` — la clé
///    publique fournie dérive bien vers l'adresse déclarée ;
/// 3. signature Ed25519 valide sur `DOMAIN_TX_V1 || champs`.
///
/// **Les trois sont obligatoires.** Sans (1), un appelant pourrait fournir
/// des informations incohérentes avec la tx. Sans (2), un attaquant pourrait
/// signer avec sa clé tout en déclarant `sender = victime`. Sans (3), la
/// preuve de possession de la clé privée est absente.
pub fn validate_signature(tx: &Transaction, sender: &SenderInfo) -> Result<(), TxValidationError> {
    // (1) Cohérence SenderInfo ↔ tx.
    if sender.address != tx.sender {
        return Err(TxValidationError::SenderInfoAddressMismatch);
    }

    // (2) Cohérence clé publique ↔ adresse déclarée.
    let derived = derive_native_address(&sender.public_key);
    if derived != tx.sender {
        return Err(TxValidationError::PublicKeyDoesNotMatchSender);
    }

    // (3) Vérification cryptographique de la signature.
    tx.verify(&sender.public_key)
        .map_err(|_| TxValidationError::InvalidSignature)?;

    Ok(())
}

/// Vérifie que le nonce de la transaction correspond au nonce attendu.
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
///
/// Rejette `max_fee < base_fee` et tout débordement de `base_fee + priority_fee`.
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

    /// Construit une transaction signée et le `SenderInfo` correspondant.
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
                public_key: pk,
                balance,
                nonce,
            },
        )
    }

    // --- SenderInfo ---------------------------------------------------------

    #[test]
    fn sender_info_from_public_key() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let pk = kp.public_key();
        let info = SenderInfo::from_public_key(pk, 100, 0);
        assert_eq!(info.address, derive_native_address(&pk));
        assert_eq!(info.public_key, pk);
        assert_eq!(info.balance, 100);
        assert_eq!(info.nonce, 0);
    }

    // --- validate_structure -------------------------------------------------

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

    // --- validate_chain_id --------------------------------------------------

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

    // --- validate_signature -------------------------------------------------

    #[test]
    fn signature_ok() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (tx, info) = signed_transfer(&kp, 0, 100, 1_000_000);
        assert!(validate_signature(&tx, &info).is_ok());
    }

    #[test]
    fn signature_rejects_sender_info_address_mismatch() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (tx, mut info) = signed_transfer(&kp, 0, 100, 1_000_000);
        // On modifie l'adresse déclarée dans SenderInfo (ne correspond plus
        // au champ `sender` de la tx).
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
        // On remplace la clé publique par une autre : l'adresse déclarée
        // dans SenderInfo reste celle de kp1 (pour ne pas déclencher
        // SenderInfoAddressMismatch), mais derive(pk2) != tx.sender.
        info.public_key = kp2.public_key();
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

    // --- validate_nonce -----------------------------------------------------

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

    // --- validate_fee -------------------------------------------------------

    #[test]
    fn fee_ok() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (tx, _) = signed_transfer(&kp, 0, 100, 1_000_000);
        // max_fee=20, priority=2, base_fee=10 → min(20, 12) = 12
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

    // --- validate_balance ---------------------------------------------------

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

    // --- validate_transaction (top-level) -----------------------------------

    #[test]
    fn full_pipeline_ok() {
        let kp = NativeKeypair::from_seed([0x42; 32]);
        let (tx, info) = signed_transfer(&kp, 0, 100, 1_000_000);
        let ctx = ValidationContext {
            expected_chain_id: chain(),
            base_fee: 10,
            sender: &info,
        };
        let v = validate_transaction(&tx, &ctx).unwrap();
        assert_eq!(v.sender, tx.sender);
        assert_eq!(v.effective_gas_price, 12);
        assert_eq!(v.max_total_fee, 21_000 * 12);
        assert_eq!(v.value, 100);
        assert_eq!(v.tx_hash, tx.hash());
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
}
