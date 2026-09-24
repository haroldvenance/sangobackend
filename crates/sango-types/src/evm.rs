//! Types EVM Ethereum-compatibles (profil Prague / Pectra).
//!
//! Ce module définit la **représentation interne** des entités EVM
//! utilisées par Sango :
//!
//! - [`EvmAccount`] : compte EVM (nonce, balance, storage root, code hash) ;
//! - [`EvmTx`] : transaction EVM typée (Legacy, EIP-2930, EIP-1559,
//!   EIP-7702) avec encodage **exactement** conforme au format Ethereum
//!   typed-transaction (`0xNN || RLP(...)`) ;
//! - [`EvmAccessList`] : access list (EIP-2930/1559/7702) ;
//! - [`EvmAuthorization`] : autorisation EIP-7702.
//!
//! ## Non duplication
//!
//! Ce module **ne duplique pas** `crate::Transaction` (transaction native
//! Sango) ni `crate::Receipt`. Une transaction native porte des champs
//! Ed25519 + `TxKind` de staking ; une transaction EVM porte des champs
//! secp256k1 + typed-tx discriminants. Les deux coexistent dans un
//! `Block::transactions` (V2+), discriminés par leur `TxKind` / forme.
//!
//! Le receipt reste [`crate::Receipt`] pour les deux domaines, avec
//! `logs` peuplés par l'EVM.
//!
//! ## Rejet V1 du type 0x03 (blob)
//!
//! EIP-4844 (type `0x03`) n'est **pas supporté** en V1. Le décodeur
//! rejette explicitement tout typed-tx commençant par `0x03` via
//! [`EvmTxError::UnsupportedTxType`]. La policy Sango V1 (`blob_transactions_enabled
//! = false` dans `EvmConfig`) est ainsi reflétée au niveau du type.
//!
//! ## Encodage
//!
//! Les transactions EVM sont encodées **exactement** comme des
//! typed-transactions Ethereum :
//!
//! ```text
//! Legacy      : RLP([nonce, gas_price, gas_limit, to, value, data, v, r, s])
//!               enveloppé en `0x00 || ...` pour le MPT et le réseau
//! EIP-2930    : 0x01 || RLP([chain_id, nonce, gas_price, gas_limit, to,
//!                           value, data, access_list, y_parity, r, s])
//! EIP-1559    : 0x02 || RLP([chain_id, nonce, max_priority_fee_per_gas,
//!                           max_fee_per_gas, gas_limit, to, value, data,
//!                           access_list, y_parity, r, s])
//! EIP-7702    : 0x04 || RLP([chain_id, nonce, max_priority_fee_per_gas,
//!                           max_fee_per_gas, gas_limit, to, value, data,
//!                           access_list, authorization_list, y_parity, r, s])
//! ```
//!
//! Aucune variante Sango n'est introduite. Les bytes produits par
//! [`EvmTx::encode_ethereum_typed`] peuvent être insérés tels quels dans
//! un MPT Ethereum (valeur d'une feuille `transaction_root`).

use rlp::{Rlp, RlpStream};
use sango_primitives::{EvmAddress, Hash32, U256};
use thiserror::Error;

// --- Constantes EVM --------------------------------------------------------

/// Plafond de gas par bloc EVM (profil Pectra).
pub const EVM_GAS_LIMIT: u64 = 30_000_000;

/// Cible de gas par bloc EVM (moitié du plafond, EIP-1559).
pub const EVM_TARGET_GAS: u64 = 15_000_000;

/// Longueur d'une clé de stockage EVM (32 bytes).
pub const EVM_STORAGE_KEY_BYTES: usize = 32;

// --- Erreurs ---------------------------------------------------------------

/// Erreur produite par l'encodage / décodage d'une transaction EVM.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EvmTxError {
    /// Le premier byte ne correspond à aucun type supporté en V1.
    ///
    /// Le type `0x03` (blob) tombe systématiquement ici.
    #[error("unsupported EVM tx type: 0x{tx_type:02x}")]
    UnsupportedTxType {
        /// Type lu.
        tx_type: u8,
    },

    /// Le payload RLP est mal formé (longueur, item count, etc.).
    #[error("malformed RLP payload")]
    MalformedRlp,

    /// Un champ entier dépasse sa taille maximale (u64, U256, etc.).
    #[error("integer overflow while decoding field: {field}")]
    IntegerOverflow {
        /// Nom du champ fautif.
        field: &'static str,
    },

    /// `y_parity` != 0 et != 1.
    #[error("invalid y_parity: {0}")]
    InvalidYParity(u8),

    /// Legacy : `v` incompatible avec EIP-155 (`v < 35`).
    #[error("legacy v < 35 (pre-EIP-155 not supported): v = {0}")]
    LegacyVTooLow(U256),

    /// EIP-7702 exige une `to` non-nulle (une adresse).
    #[error("EIP-7702 requires a non-empty `to`")]
    MissingToForEip7702,

    /// Une access list item a une clé de stockage de taille != 32.
    #[error("access list storage key has invalid length: {0}")]
    InvalidStorageKeyLength(usize),
}

// --- Discriminants ---------------------------------------------------------

/// Discriminant d'une transaction EVM typée.
///
/// Les valeurs correspondent aux tags du réseau Ethereum. **Le type `0x03`
/// (blob) est listé mais rejeté en V1** — il est présent pour rendre le
/// rejet explicite et détectable.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum EvmTxKind {
    /// Legacy (pré-EIP-2718), envelopé en `0x00` dans les contextes typés.
    Legacy = 0x00,
    /// EIP-2930 : transaction typée avec access list et `gas_price` unique.
    Eip2930 = 0x01,
    /// EIP-1559 : `max_fee_per_gas` + `max_priority_fee_per_gas`.
    Eip1559 = 0x02,
    /// EIP-4844 : transaction blob. **Rejetée en V1.**
    Eip4844 = 0x03,
    /// EIP-7702 : `authorization_list` (délégation de code).
    Eip7702 = 0x04,
}

impl EvmTxKind {
    /// Tag canonique `u8`.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Parse un tag canonique.
    ///
    /// Le type `0x03` renvoie une erreur explicite : V1 ne l'accepte pas.
    pub fn from_tag(tag: u8) -> Result<Self, EvmTxError> {
        match tag {
            0x00 => Ok(EvmTxKind::Legacy),
            0x01 => Ok(EvmTxKind::Eip2930),
            0x02 => Ok(EvmTxKind::Eip1559),
            0x04 => Ok(EvmTxKind::Eip7702),
            // 0x03 (blob) : rejet explicite V1.
            other => Err(EvmTxError::UnsupportedTxType { tx_type: other }),
        }
    }

    /// Vrai si ce type est accepté par la policy V1 Sango.
    #[must_use]
    pub const fn is_accepted_v1(self) -> bool {
        !matches!(self, EvmTxKind::Eip4844)
    }
}

// --- Constantes EVM normatives ---------------------------------------------

/// `Keccak256(&[])` — hash du code **vide** en Ethereum.
///
/// Constante normative Ethereum, identique à celle utilisée par geth,
/// revm et tous les clients Ethereum :
///
/// ```text
/// 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
/// ```
///
/// Utilisée comme `code_hash` initial d'un compte sans bytecode
/// (EOA, ou contrat pas encore déployé). **Ce n'est pas `Hash32::ZERO`.**
#[must_use]
pub fn empty_code_hash() -> Hash32 {
    sango_crypto::keccak256(&[])
}

/// `Keccak256(RLP(""))` — racine d'un MPT Ethereum **vide**.
///
/// Constante normative Ethereum :
///
/// ```text
/// 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421
/// ```
///
/// RLP d'une chaîne vide est le byte unique `0x80`. Utilisée comme
/// `storage_root` initial d'un compte sans storage. **Ce n'est pas
/// `Hash32::ZERO`.**
///
/// Équivalent à `sango_mpt::empty_root()` — on duplique la formule ici
/// pour éviter une dépendance `sango-types → sango-mpt`.
#[must_use]
pub fn evm_empty_trie_root() -> Hash32 {
    sango_crypto::keccak256(&[0x80])
}

// --- Compte EVM ------------------------------------------------------------

/// Compte EVM tel que stocké dans le state trie Ethereum.
///
/// ## Encodage Ethereum (RLP) du compte
///
/// ```text
/// RLP([nonce, balance, storage_root, code_hash])
/// ```
///
/// Clé du compte dans le state trie : `Keccak256(evm_address)` (32 bytes).
///
/// ## Balances
///
/// `balance` est un `U256` libellé en **base units SANGO**. Le format de
/// compte est identique à Ethereum Prague — aucune divergence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct EvmAccount {
    /// Nonce du compte (nombre de transactions émises).
    pub nonce: u64,
    /// Balance en base units SANGO, représentée en `U256` (comme Ethereum).
    pub balance: U256,
    /// Racine du storage trie du compte (MPT Ethereum).
    pub storage_root: Hash32,
    /// `Keccak256(code)` — ou `Keccak256(&[])` si le compte n'a pas de code.
    pub code_hash: Hash32,
}

impl EvmAccount {
    /// Compte EVM vide (nonce 0, balance 0, storage vide, code vide).
    ///
    /// Utilise les constantes normatives Ethereum :
    ///
    /// - `storage_root = evm_empty_trie_root()` = `Keccak256(RLP(""))` ;
    /// - `code_hash = empty_code_hash()` = `Keccak256(&[])`.
    ///
    /// **Ce ne sont pas des `Hash32::ZERO`.** Voir les constantes pour
    /// les valeurs exactes et leur justification.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            nonce: 0,
            balance: U256::ZERO,
            storage_root: evm_empty_trie_root(),
            code_hash: empty_code_hash(),
        }
    }

    /// Vrai si le compte est vierge (aucune activité on-chain) au sens
    /// Ethereum : nonce = 0, balance = 0, code = vide.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nonce == 0 && self.balance == U256::ZERO && self.code_hash == empty_code_hash()
    }
}

// --- Access list -----------------------------------------------------------

/// Item d'access list EVM (EIP-2930, EIP-1559, EIP-7702).
///
/// Format Ethereum :
///
/// ```text
/// RLP([address, [storage_key_1, storage_key_2, ...]])
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvmAccessListItem {
    /// Adresse ciblée par l'access list.
    pub address: EvmAddress,
    /// Clés de stockage (32 bytes chacune).
    pub storage_keys: Vec<Hash32>,
}

/// Access list EVM — liste ordonnée d'items.
///
/// La sémantique Ethereum exige l'ordre **tel que fourni par l'expéditeur**
/// (l'ordre fait partie de la signature). Cet alias `Vec<...>` reflète cette
/// contrainte : aucune normalisation n'est appliquée à l'encodage.
pub type EvmAccessList = Vec<EvmAccessListItem>;

// --- Autorisation EIP-7702 -------------------------------------------------

/// Autorisation EIP-7702 : délégation d'un compte EOA vers un contrat.
///
/// Format Ethereum :
///
/// ```text
/// RLP([chain_id, address, nonce, y_parity, r, s])
/// ```
///
/// `chain_id` vaut `0` pour « n'importe quelle chaîne », sinon le chain ID
/// EVM attendu.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct EvmAuthorization {
    /// Chain ID EVM ciblé (`0` = any chain).
    pub chain_id: U256,
    /// Adresse du contrat délégataire.
    pub address: EvmAddress,
    /// Nonce du compte EOA émetteur.
    pub nonce: u64,
    /// Bit `y_parity` de la signature secp256k1 (`0` ou `1`).
    pub y_parity: u8,
    /// Composant `r` de la signature.
    pub r: U256,
    /// Composant `s` de la signature.
    pub s: U256,
}

// --- Transaction EVM -------------------------------------------------------

/// Transaction EVM typée.
///
/// Représentation interne des 4 types supportés en V1. Le 5ᵉ (EIP-4844,
/// `0x03`) est rejeté par [`EvmTx::decode_ethereum_typed`].
///
/// ## Champ `to`
///
/// - `Some(addr)` : appel à un contrat / transfert vers un EOA ;
/// - `None` : création de contrat. **Interdit** pour EIP-7702.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvmTx {
    /// Legacy (pré-EIP-2718), encodée dans les contextes typés avec un
    /// préfixe `0x00`.
    Legacy {
        /// Chain ID (post-EIP-155 obligatoire).
        chain_id: u64,
        /// Nonce de l'émetteur.
        nonce: u64,
        /// Prix du gas (unique).
        gas_price: U256,
        /// Limite de gas.
        gas_limit: u64,
        /// Destinataire, ou `None` pour une création de contrat.
        to: Option<EvmAddress>,
        /// Montant transféré (base units SANGO).
        value: U256,
        /// Payload (input pour un call, bytecode pour un create).
        data: Vec<u8>,
        /// Bit `y_parity` (`0` ou `1`).
        y_parity: u8,
        /// Composant `r` de la signature secp256k1.
        r: U256,
        /// Composant `s`.
        s: U256,
    },

    /// EIP-2930 : access list + `gas_price` unique.
    Eip2930 {
        /// Chain ID EVM.
        chain_id: u64,
        /// Nonce de l'émetteur.
        nonce: u64,
        /// Prix du gas (unique).
        gas_price: U256,
        /// Limite de gas.
        gas_limit: u64,
        /// Destinataire, ou `None` pour une création.
        to: Option<EvmAddress>,
        /// Montant transféré.
        value: U256,
        /// Payload.
        data: Vec<u8>,
        /// Access list.
        access_list: EvmAccessList,
        /// Bit `y_parity`.
        y_parity: u8,
        /// Composant `r`.
        r: U256,
        /// Composant `s`.
        s: U256,
    },

    /// EIP-1559 : `max_fee_per_gas` + `max_priority_fee_per_gas` + access
    /// list.
    Eip1559 {
        /// Chain ID EVM.
        chain_id: u64,
        /// Nonce de l'émetteur.
        nonce: u64,
        /// Pourboire maximal au validateur (par unité de gas).
        max_priority_fee_per_gas: U256,
        /// Frais totaux maximaux (par unité de gas).
        max_fee_per_gas: U256,
        /// Limite de gas.
        gas_limit: u64,
        /// Destinataire, ou `None` pour une création.
        to: Option<EvmAddress>,
        /// Montant transféré.
        value: U256,
        /// Payload.
        data: Vec<u8>,
        /// Access list.
        access_list: EvmAccessList,
        /// Bit `y_parity`.
        y_parity: u8,
        /// Composant `r`.
        r: U256,
        /// Composant `s`.
        s: U256,
    },

    /// EIP-7702 : EIP-1559 + `authorization_list`. `to` est obligatoire.
    Eip7702 {
        /// Chain ID EVM.
        chain_id: u64,
        /// Nonce de l'émetteur.
        nonce: u64,
        /// Pourboire maximal au validateur.
        max_priority_fee_per_gas: U256,
        /// Frais totaux maximaux.
        max_fee_per_gas: U256,
        /// Limite de gas.
        gas_limit: u64,
        /// Destinataire (obligatoire pour EIP-7702).
        to: EvmAddress,
        /// Montant transféré.
        value: U256,
        /// Payload.
        data: Vec<u8>,
        /// Access list.
        access_list: EvmAccessList,
        /// Liste d'autorisations de délégation.
        authorization_list: Vec<EvmAuthorization>,
        /// Bit `y_parity`.
        y_parity: u8,
        /// Composant `r`.
        r: U256,
        /// Composant `s`.
        s: U256,
    },
}

impl EvmTx {
    /// Discriminant de la transaction.
    #[must_use]
    pub fn kind(&self) -> EvmTxKind {
        match self {
            EvmTx::Legacy { .. } => EvmTxKind::Legacy,
            EvmTx::Eip2930 { .. } => EvmTxKind::Eip2930,
            EvmTx::Eip1559 { .. } => EvmTxKind::Eip1559,
            EvmTx::Eip7702 { .. } => EvmTxKind::Eip7702,
        }
    }

    /// Nonce de l'émetteur.
    #[must_use]
    pub fn nonce(&self) -> u64 {
        match self {
            EvmTx::Legacy { nonce, .. }
            | EvmTx::Eip2930 { nonce, .. }
            | EvmTx::Eip1559 { nonce, .. }
            | EvmTx::Eip7702 { nonce, .. } => *nonce,
        }
    }

    /// Limite de gas.
    #[must_use]
    pub fn gas_limit(&self) -> u64 {
        match self {
            EvmTx::Legacy { gas_limit, .. }
            | EvmTx::Eip2930 { gas_limit, .. }
            | EvmTx::Eip1559 { gas_limit, .. }
            | EvmTx::Eip7702 { gas_limit, .. } => *gas_limit,
        }
    }

    /// Destinataire, ou `None` pour une création de contrat.
    #[must_use]
    pub fn to(&self) -> Option<EvmAddress> {
        match self {
            EvmTx::Legacy { to, .. } | EvmTx::Eip2930 { to, .. } | EvmTx::Eip1559 { to, .. } => *to,
            EvmTx::Eip7702 { to, .. } => Some(*to),
        }
    }

    /// Vrai si la transaction crée un contrat.
    #[must_use]
    pub fn is_contract_creation(&self) -> bool {
        self.to().is_none()
    }

    /// Montant transféré.
    #[must_use]
    pub fn value(&self) -> U256 {
        match self {
            EvmTx::Legacy { value, .. }
            | EvmTx::Eip2930 { value, .. }
            | EvmTx::Eip1559 { value, .. }
            | EvmTx::Eip7702 { value, .. } => *value,
        }
    }

    /// Payload brut.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        match self {
            EvmTx::Legacy { data, .. }
            | EvmTx::Eip2930 { data, .. }
            | EvmTx::Eip1559 { data, .. }
            | EvmTx::Eip7702 { data, .. } => data.as_slice(),
        }
    }

    /// Encode en **Ethereum typed transaction** exact.
    ///
    /// Format produit :
    ///
    /// ```text
    /// Legacy   : 0x00 || RLP([nonce, gas_price, gas_limit, to, value,
    ///                        data, v, r, s])
    /// EIP-2930 : 0x01 || RLP([chain_id, nonce, gas_price, gas_limit, to,
    ///                        value, data, access_list, y_parity, r, s])
    /// EIP-1559 : 0x02 || RLP([chain_id, nonce, max_priority_fee_per_gas,
    ///                        max_fee_per_gas, gas_limit, to, value, data,
    ///                        access_list, y_parity, r, s])
    /// EIP-7702 : 0x04 || RLP([chain_id, nonce, max_priority_fee_per_gas,
    ///                        max_fee_per_gas, gas_limit, to, value, data,
    ///                        access_list, authorization_list, y_parity, r, s])
    /// ```
    ///
    /// Pour Legacy, `v = chain_id * 2 + 35 + y_parity` (EIP-155).
    #[must_use]
    pub fn encode_ethereum_typed(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            EvmTx::Legacy {
                chain_id,
                nonce,
                gas_price,
                gas_limit,
                to,
                value,
                data,
                y_parity,
                r,
                s,
            } => {
                out.push(EvmTxKind::Legacy.tag());
                let v: U256 = legacy_v(*chain_id, *y_parity);
                let mut stream = RlpStream::new_list(9);
                encode_u64(&mut stream, *nonce);
                encode_u256(&mut stream, *gas_price);
                encode_u64(&mut stream, *gas_limit);
                encode_to(&mut stream, *to);
                encode_u256(&mut stream, *value);
                stream.append(&data.as_slice());
                encode_u256(&mut stream, v);
                encode_u256(&mut stream, *r);
                encode_u256(&mut stream, *s);
                out.extend_from_slice(&stream.out());
            }
            EvmTx::Eip2930 {
                chain_id,
                nonce,
                gas_price,
                gas_limit,
                to,
                value,
                data,
                access_list,
                y_parity,
                r,
                s,
            } => {
                out.push(EvmTxKind::Eip2930.tag());
                let mut stream = RlpStream::new_list(11);
                encode_u64(&mut stream, *chain_id);
                encode_u64(&mut stream, *nonce);
                encode_u256(&mut stream, *gas_price);
                encode_u64(&mut stream, *gas_limit);
                encode_to(&mut stream, *to);
                encode_u256(&mut stream, *value);
                stream.append(&data.as_slice());
                encode_access_list(&mut stream, access_list);
                encode_u64(&mut stream, *y_parity as u64);
                encode_u256(&mut stream, *r);
                encode_u256(&mut stream, *s);
                out.extend_from_slice(&stream.out());
            }
            EvmTx::Eip1559 {
                chain_id,
                nonce,
                max_priority_fee_per_gas,
                max_fee_per_gas,
                gas_limit,
                to,
                value,
                data,
                access_list,
                y_parity,
                r,
                s,
            } => {
                out.push(EvmTxKind::Eip1559.tag());
                let mut stream = RlpStream::new_list(12);
                encode_u64(&mut stream, *chain_id);
                encode_u64(&mut stream, *nonce);
                encode_u256(&mut stream, *max_priority_fee_per_gas);
                encode_u256(&mut stream, *max_fee_per_gas);
                encode_u64(&mut stream, *gas_limit);
                encode_to(&mut stream, *to);
                encode_u256(&mut stream, *value);
                stream.append(&data.as_slice());
                encode_access_list(&mut stream, access_list);
                encode_u64(&mut stream, *y_parity as u64);
                encode_u256(&mut stream, *r);
                encode_u256(&mut stream, *s);
                out.extend_from_slice(&stream.out());
            }
            EvmTx::Eip7702 {
                chain_id,
                nonce,
                max_priority_fee_per_gas,
                max_fee_per_gas,
                gas_limit,
                to,
                value,
                data,
                access_list,
                authorization_list,
                y_parity,
                r,
                s,
            } => {
                out.push(EvmTxKind::Eip7702.tag());
                let mut stream = RlpStream::new_list(13);
                encode_u64(&mut stream, *chain_id);
                encode_u64(&mut stream, *nonce);
                encode_u256(&mut stream, *max_priority_fee_per_gas);
                encode_u256(&mut stream, *max_fee_per_gas);
                encode_u64(&mut stream, *gas_limit);
                let to_bytes: &[u8] = to.as_bytes();
                stream.append(&to_bytes);
                encode_u256(&mut stream, *value);
                stream.append(&data.as_slice());
                encode_access_list(&mut stream, access_list);
                encode_authorization_list(&mut stream, authorization_list);
                encode_u64(&mut stream, *y_parity as u64);
                encode_u256(&mut stream, *r);
                encode_u256(&mut stream, *s);
                out.extend_from_slice(&stream.out());
            }
        }
        out
    }

    /// Décode depuis une **Ethereum typed transaction** exacte.
    ///
    /// Rejette :
    ///
    /// - les types non supportés (`0x03` et tout byte inconnu) via
    ///   [`EvmTxError::UnsupportedTxType`] ;
    /// - `y_parity ∉ {0, 1}` ;
    /// - Legacy avec `v < 35` (pre-EIP-155) ;
    /// - EIP-7702 sans `to` ;
    /// - toute longueur RLP incohérente.
    pub fn decode_ethereum_typed(bytes: &[u8]) -> Result<Self, EvmTxError> {
        if bytes.is_empty() {
            return Err(EvmTxError::MalformedRlp);
        }
        let kind = EvmTxKind::from_tag(bytes[0])?;
        let payload = &bytes[1..];
        let rlp = Rlp::new(payload);

        match kind {
            EvmTxKind::Legacy => decode_legacy(&rlp),
            EvmTxKind::Eip2930 => decode_eip2930(&rlp),
            EvmTxKind::Eip1559 => decode_eip1559(&rlp),
            EvmTxKind::Eip7702 => decode_eip7702(&rlp),
            EvmTxKind::Eip4844 => Err(EvmTxError::UnsupportedTxType {
                tx_type: EvmTxKind::Eip4844.tag(),
            }),
        }
    }
}

// --- Helpers d'encodage RLP ------------------------------------------------

fn encode_u64(s: &mut RlpStream, v: u64) {
    let bytes = v.to_be_bytes();
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(8);
    let slice: &[u8] = &bytes[start..];
    s.append(&slice);
}

fn encode_u256(s: &mut RlpStream, v: U256) {
    let bytes = v.to_be_bytes::<32>();
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(32);
    let slice: &[u8] = &bytes[start..];
    s.append(&slice);
}

fn encode_to(s: &mut RlpStream, to: Option<EvmAddress>) {
    match to {
        Some(a) => {
            let bytes: &[u8] = a.as_bytes();
            s.append(&bytes);
        }
        None => {
            s.append_empty_data();
        }
    }
}

fn encode_access_list(s: &mut RlpStream, list: &EvmAccessList) {
    s.begin_list(list.len());
    for item in list {
        s.begin_list(2);
        let addr_bytes: &[u8] = item.address.as_bytes();
        s.append(&addr_bytes);
        s.begin_list(item.storage_keys.len());
        for key in &item.storage_keys {
            let key_bytes: &[u8] = key.as_bytes();
            s.append(&key_bytes);
        }
    }
}

fn encode_authorization_list(s: &mut RlpStream, list: &[EvmAuthorization]) {
    s.begin_list(list.len());
    for auth in list {
        s.begin_list(6);
        encode_u256(s, auth.chain_id);
        let addr_bytes: &[u8] = auth.address.as_bytes();
        s.append(&addr_bytes);
        encode_u64(s, auth.nonce);
        encode_u64(s, auth.y_parity as u64);
        encode_u256(s, auth.r);
        encode_u256(s, auth.s);
    }
}

/// Calcule `v` pour une Legacy EIP-155 : `chain_id * 2 + 35 + y_parity`.
fn legacy_v(chain_id: u64, y_parity: u8) -> U256 {
    let v_u64 = chain_id
        .saturating_mul(2)
        .saturating_add(35)
        .saturating_add(y_parity as u64);
    U256::from(v_u64)
}

// --- Helpers de décodage RLP -----------------------------------------------

fn decode_u64(rlp: &Rlp, field: &'static str) -> Result<u64, EvmTxError> {
    let bytes = rlp.data().map_err(|_| EvmTxError::MalformedRlp)?;
    if bytes.len() > 8 {
        return Err(EvmTxError::IntegerOverflow { field });
    }
    let mut buf = [0u8; 8];
    buf[8 - bytes.len()..].copy_from_slice(bytes);
    Ok(u64::from_be_bytes(buf))
}

fn decode_u256(rlp: &Rlp) -> Result<U256, EvmTxError> {
    let bytes = rlp.data().map_err(|_| EvmTxError::MalformedRlp)?;
    if bytes.len() > 32 {
        return Err(EvmTxError::MalformedRlp);
    }
    let mut buf = [0u8; 32];
    buf[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(U256::from_be_bytes(buf))
}

fn decode_y_parity(rlp: &Rlp, index: usize) -> Result<u8, EvmTxError> {
    let b: u8 = rlp.val_at(index).map_err(|_| EvmTxError::MalformedRlp)?;
    if b > 1 {
        return Err(EvmTxError::InvalidYParity(b));
    }
    Ok(b)
}

fn decode_to(rlp: &Rlp, index: usize) -> Result<Option<EvmAddress>, EvmTxError> {
    let bytes: Vec<u8> = rlp.val_at(index).map_err(|_| EvmTxError::MalformedRlp)?;
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() != 20 {
        return Err(EvmTxError::MalformedRlp);
    }
    let mut buf = [0u8; 20];
    buf.copy_from_slice(&bytes);
    Ok(Some(EvmAddress::from_bytes(buf)))
}

fn decode_access_list(rlp: &Rlp, index: usize) -> Result<EvmAccessList, EvmTxError> {
    let list = rlp.at(index).map_err(|_| EvmTxError::MalformedRlp)?;
    if !list.is_list() {
        return Err(EvmTxError::MalformedRlp);
    }
    let count = list.item_count().map_err(|_| EvmTxError::MalformedRlp)?;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let item = list.at(i).map_err(|_| EvmTxError::MalformedRlp)?;
        let addr_bytes: Vec<u8> = item.val_at(0).map_err(|_| EvmTxError::MalformedRlp)?;
        if addr_bytes.len() != 20 {
            return Err(EvmTxError::MalformedRlp);
        }
        let mut abuf = [0u8; 20];
        abuf.copy_from_slice(&addr_bytes);
        let address = EvmAddress::from_bytes(abuf);

        let keys_rlp = item.at(1).map_err(|_| EvmTxError::MalformedRlp)?;
        let nkeys = keys_rlp
            .item_count()
            .map_err(|_| EvmTxError::MalformedRlp)?;
        let mut storage_keys = Vec::with_capacity(nkeys);
        for j in 0..nkeys {
            let kb: Vec<u8> = keys_rlp.val_at(j).map_err(|_| EvmTxError::MalformedRlp)?;
            if kb.len() != EVM_STORAGE_KEY_BYTES {
                return Err(EvmTxError::InvalidStorageKeyLength(kb.len()));
            }
            let mut kbuf = [0u8; 32];
            kbuf.copy_from_slice(&kb);
            storage_keys.push(Hash32::from_bytes(kbuf));
        }
        out.push(EvmAccessListItem {
            address,
            storage_keys,
        });
    }
    Ok(out)
}

fn decode_authorization_list(rlp: &Rlp, index: usize) -> Result<Vec<EvmAuthorization>, EvmTxError> {
    let list = rlp.at(index).map_err(|_| EvmTxError::MalformedRlp)?;
    let count = list.item_count().map_err(|_| EvmTxError::MalformedRlp)?;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let auth = list.at(i).map_err(|_| EvmTxError::MalformedRlp)?;
        let chain_id = decode_u256(&auth.at(0).map_err(|_| EvmTxError::MalformedRlp)?)?;
        let addr_bytes: Vec<u8> = auth.val_at(1).map_err(|_| EvmTxError::MalformedRlp)?;
        if addr_bytes.len() != 20 {
            return Err(EvmTxError::MalformedRlp);
        }
        let mut abuf = [0u8; 20];
        abuf.copy_from_slice(&addr_bytes);
        let address = EvmAddress::from_bytes(abuf);
        let nonce = decode_u64(&auth.at(2).map_err(|_| EvmTxError::MalformedRlp)?, "nonce")?;
        let y_parity = decode_y_parity(&auth, 3)?;
        let r = decode_u256(&auth.at(4).map_err(|_| EvmTxError::MalformedRlp)?)?;
        let s = decode_u256(&auth.at(5).map_err(|_| EvmTxError::MalformedRlp)?)?;
        out.push(EvmAuthorization {
            chain_id,
            address,
            nonce,
            y_parity,
            r,
            s,
        });
    }
    Ok(out)
}

// --- Décodage par type ------------------------------------------------------

fn decode_legacy(rlp: &Rlp) -> Result<EvmTx, EvmTxError> {
    if rlp.item_count().map_err(|_| EvmTxError::MalformedRlp)? != 9 {
        return Err(EvmTxError::MalformedRlp);
    }
    let nonce = decode_u64(&rlp.at(0).map_err(|_| EvmTxError::MalformedRlp)?, "nonce")?;
    let gas_price = decode_u256(&rlp.at(1).map_err(|_| EvmTxError::MalformedRlp)?)?;
    let gas_limit = decode_u64(
        &rlp.at(2).map_err(|_| EvmTxError::MalformedRlp)?,
        "gas_limit",
    )?;
    let to = decode_to(rlp, 3)?;
    let value = decode_u256(&rlp.at(4).map_err(|_| EvmTxError::MalformedRlp)?)?;
    let data: Vec<u8> = rlp.val_at(5).map_err(|_| EvmTxError::MalformedRlp)?;
    let v = decode_u256(&rlp.at(6).map_err(|_| EvmTxError::MalformedRlp)?)?;
    let r = decode_u256(&rlp.at(7).map_err(|_| EvmTxError::MalformedRlp)?)?;
    let s = decode_u256(&rlp.at(8).map_err(|_| EvmTxError::MalformedRlp)?)?;

    // EIP-155 : v = chain_id * 2 + 35 + y_parity
    let v_u64 = u64::try_from(v).map_err(|_| EvmTxError::LegacyVTooLow(v))?;
    if v_u64 < 35 {
        return Err(EvmTxError::LegacyVTooLow(v));
    }
    let chain_id = (v_u64 - 35) / 2;
    let y_parity = ((v_u64 - 35) % 2) as u8;

    Ok(EvmTx::Legacy {
        chain_id,
        nonce,
        gas_price,
        gas_limit,
        to,
        value,
        data,
        y_parity,
        r,
        s,
    })
}

fn decode_eip2930(rlp: &Rlp) -> Result<EvmTx, EvmTxError> {
    if rlp.item_count().map_err(|_| EvmTxError::MalformedRlp)? != 11 {
        return Err(EvmTxError::MalformedRlp);
    }
    let chain_id = decode_u64(
        &rlp.at(0).map_err(|_| EvmTxError::MalformedRlp)?,
        "chain_id",
    )?;
    let nonce = decode_u64(&rlp.at(1).map_err(|_| EvmTxError::MalformedRlp)?, "nonce")?;
    let gas_price = decode_u256(&rlp.at(2).map_err(|_| EvmTxError::MalformedRlp)?)?;
    let gas_limit = decode_u64(
        &rlp.at(3).map_err(|_| EvmTxError::MalformedRlp)?,
        "gas_limit",
    )?;
    let to = decode_to(rlp, 4)?;
    let value = decode_u256(&rlp.at(5).map_err(|_| EvmTxError::MalformedRlp)?)?;
    let data: Vec<u8> = rlp.val_at(6).map_err(|_| EvmTxError::MalformedRlp)?;
    let access_list = decode_access_list(rlp, 7)?;
    let y_parity = decode_y_parity(rlp, 8)?;
    let r = decode_u256(&rlp.at(9).map_err(|_| EvmTxError::MalformedRlp)?)?;
    let s = decode_u256(&rlp.at(10).map_err(|_| EvmTxError::MalformedRlp)?)?;

    Ok(EvmTx::Eip2930 {
        chain_id,
        nonce,
        gas_price,
        gas_limit,
        to,
        value,
        data,
        access_list,
        y_parity,
        r,
        s,
    })
}

fn decode_eip1559(rlp: &Rlp) -> Result<EvmTx, EvmTxError> {
    if rlp.item_count().map_err(|_| EvmTxError::MalformedRlp)? != 12 {
        return Err(EvmTxError::MalformedRlp);
    }
    let chain_id = decode_u64(
        &rlp.at(0).map_err(|_| EvmTxError::MalformedRlp)?,
        "chain_id",
    )?;
    let nonce = decode_u64(&rlp.at(1).map_err(|_| EvmTxError::MalformedRlp)?, "nonce")?;
    let max_priority_fee_per_gas = decode_u256(&rlp.at(2).map_err(|_| EvmTxError::MalformedRlp)?)?;
    let max_fee_per_gas = decode_u256(&rlp.at(3).map_err(|_| EvmTxError::MalformedRlp)?)?;
    let gas_limit = decode_u64(
        &rlp.at(4).map_err(|_| EvmTxError::MalformedRlp)?,
        "gas_limit",
    )?;
    let to = decode_to(rlp, 5)?;
    let value = decode_u256(&rlp.at(6).map_err(|_| EvmTxError::MalformedRlp)?)?;
    let data: Vec<u8> = rlp.val_at(7).map_err(|_| EvmTxError::MalformedRlp)?;
    let access_list = decode_access_list(rlp, 8)?;
    let y_parity = decode_y_parity(rlp, 9)?;
    let r = decode_u256(&rlp.at(10).map_err(|_| EvmTxError::MalformedRlp)?)?;
    let s = decode_u256(&rlp.at(11).map_err(|_| EvmTxError::MalformedRlp)?)?;

    Ok(EvmTx::Eip1559 {
        chain_id,
        nonce,
        max_priority_fee_per_gas,
        max_fee_per_gas,
        gas_limit,
        to,
        value,
        data,
        access_list,
        y_parity,
        r,
        s,
    })
}

fn decode_eip7702(rlp: &Rlp) -> Result<EvmTx, EvmTxError> {
    if rlp.item_count().map_err(|_| EvmTxError::MalformedRlp)? != 13 {
        return Err(EvmTxError::MalformedRlp);
    }
    let chain_id = decode_u64(
        &rlp.at(0).map_err(|_| EvmTxError::MalformedRlp)?,
        "chain_id",
    )?;
    let nonce = decode_u64(&rlp.at(1).map_err(|_| EvmTxError::MalformedRlp)?, "nonce")?;
    let max_priority_fee_per_gas = decode_u256(&rlp.at(2).map_err(|_| EvmTxError::MalformedRlp)?)?;
    let max_fee_per_gas = decode_u256(&rlp.at(3).map_err(|_| EvmTxError::MalformedRlp)?)?;
    let gas_limit = decode_u64(
        &rlp.at(4).map_err(|_| EvmTxError::MalformedRlp)?,
        "gas_limit",
    )?;
    let to = decode_to(rlp, 5)?.ok_or(EvmTxError::MissingToForEip7702)?;
    let value = decode_u256(&rlp.at(6).map_err(|_| EvmTxError::MalformedRlp)?)?;
    let data: Vec<u8> = rlp.val_at(7).map_err(|_| EvmTxError::MalformedRlp)?;
    let access_list = decode_access_list(rlp, 8)?;
    let authorization_list = decode_authorization_list(rlp, 9)?;
    let y_parity = decode_y_parity(rlp, 10)?;
    let r = decode_u256(&rlp.at(11).map_err(|_| EvmTxError::MalformedRlp)?)?;
    let s = decode_u256(&rlp.at(12).map_err(|_| EvmTxError::MalformedRlp)?)?;

    Ok(EvmTx::Eip7702 {
        chain_id,
        nonce,
        max_priority_fee_per_gas,
        max_fee_per_gas,
        gas_limit,
        to,
        value,
        data,
        access_list,
        authorization_list,
        y_parity,
        r,
        s,
    })
}

// --- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sango_primitives::Hash32;

    fn addr(b: u8) -> EvmAddress {
        EvmAddress::from_bytes([b; 20])
    }

    fn h(b: u8) -> Hash32 {
        Hash32::from_bytes([b; 32])
    }

    fn u(v: u64) -> U256 {
        U256::from(v)
    }

    // --- EvmTxKind ----------------------------------------------------------

    #[test]
    fn evm_tx_kind_tags_roundtrip() {
        for k in [
            EvmTxKind::Legacy,
            EvmTxKind::Eip2930,
            EvmTxKind::Eip1559,
            EvmTxKind::Eip7702,
        ] {
            assert_eq!(EvmTxKind::from_tag(k.tag()).unwrap(), k);
        }
    }

    #[test]
    fn evm_tx_kind_rejects_blob_4844() {
        let err = EvmTxKind::from_tag(0x03).unwrap_err();
        assert_eq!(err, EvmTxError::UnsupportedTxType { tx_type: 0x03 });
    }

    #[test]
    fn evm_tx_kind_rejects_unknown() {
        assert!(EvmTxKind::from_tag(0x05).is_err());
        assert!(EvmTxKind::from_tag(0xff).is_err());
    }

    #[test]
    fn evm_tx_kind_accepted_v1() {
        assert!(EvmTxKind::Legacy.is_accepted_v1());
        assert!(EvmTxKind::Eip2930.is_accepted_v1());
        assert!(EvmTxKind::Eip1559.is_accepted_v1());
        assert!(EvmTxKind::Eip7702.is_accepted_v1());
        assert!(!EvmTxKind::Eip4844.is_accepted_v1());
    }

    // --- EvmAccount ---------------------------------------------------------

    #[test]
    fn evm_account_empty() {
        let a = EvmAccount::empty();
        assert_eq!(a.nonce, 0);
        assert_eq!(a.balance, U256::ZERO);
        assert!(a.is_empty());
    }

    #[test]
    fn evm_account_non_empty() {
        let a = EvmAccount {
            nonce: 5,
            balance: u(1000),
            storage_root: h(0x11),
            code_hash: h(0x22),
        };
        assert!(!a.is_empty());
    }

    // --- Legacy -------------------------------------------------------------

    #[test]
    fn legacy_roundtrip_creation() {
        let tx = EvmTx::Legacy {
            chain_id: 7777,
            nonce: 0,
            gas_price: u(20_000_000_000),
            gas_limit: 100_000,
            to: None, // création
            value: u(0),
            data: vec![0x60, 0x00, 0x60, 0x00],
            y_parity: 1,
            r: U256::from(0xdead_beef_u64),
            s: U256::from(0xfeed_face_u64),
        };
        let bytes = tx.encode_ethereum_typed();
        assert_eq!(bytes[0], 0x00);
        let decoded = EvmTx::decode_ethereum_typed(&bytes).unwrap();
        assert_eq!(decoded, tx);
    }

    #[test]
    fn legacy_roundtrip_call() {
        let tx = EvmTx::Legacy {
            chain_id: 1,
            nonce: 42,
            gas_price: u(1),
            gas_limit: 21_000,
            to: Some(addr(0xaa)),
            value: u(1_000_000),
            data: vec![],
            y_parity: 0,
            r: U256::from(7u64),
            s: U256::from(11u64),
        };
        let bytes = tx.encode_ethereum_typed();
        let decoded = EvmTx::decode_ethereum_typed(&bytes).unwrap();
        assert_eq!(decoded, tx);
    }

    // --- EIP-2930 -----------------------------------------------------------

    #[test]
    fn eip2930_roundtrip() {
        let tx = EvmTx::Eip2930 {
            chain_id: 7777,
            nonce: 1,
            gas_price: u(1_000_000_000),
            gas_limit: 50_000,
            to: Some(addr(0x11)),
            value: u(0),
            data: vec![0xde, 0xad],
            access_list: vec![EvmAccessListItem {
                address: addr(0x22),
                storage_keys: vec![h(0x01), h(0x02)],
            }],
            y_parity: 1,
            r: U256::from(3u64),
            s: U256::from(4u64),
        };
        let bytes = tx.encode_ethereum_typed();
        assert_eq!(bytes[0], 0x01);
        let decoded = EvmTx::decode_ethereum_typed(&bytes).unwrap();
        assert_eq!(decoded, tx);
    }

    // --- EIP-1559 -----------------------------------------------------------

    #[test]
    fn eip1559_roundtrip() {
        let tx = EvmTx::Eip1559 {
            chain_id: 7777,
            nonce: 5,
            max_priority_fee_per_gas: u(1_000_000),
            max_fee_per_gas: u(50_000_000_000),
            gas_limit: 21_000,
            to: Some(addr(0xcc)),
            value: u(12_345),
            data: vec![],
            access_list: vec![],
            y_parity: 0,
            r: U256::from(99u64),
            s: U256::from(77u64),
        };
        let bytes = tx.encode_ethereum_typed();
        assert_eq!(bytes[0], 0x02);
        let decoded = EvmTx::decode_ethereum_typed(&bytes).unwrap();
        assert_eq!(decoded, tx);
    }

    #[test]
    fn eip1559_creation_roundtrip() {
        let tx = EvmTx::Eip1559 {
            chain_id: 7777,
            nonce: 0,
            max_priority_fee_per_gas: u(2),
            max_fee_per_gas: u(100),
            gas_limit: 200_000,
            to: None,
            value: u(0),
            data: vec![0x01, 0x02, 0x03],
            access_list: vec![EvmAccessListItem {
                address: addr(0xdd),
                storage_keys: vec![],
            }],
            y_parity: 1,
            r: U256::from(1u64),
            s: U256::from(2u64),
        };
        let bytes = tx.encode_ethereum_typed();
        let decoded = EvmTx::decode_ethereum_typed(&bytes).unwrap();
        assert_eq!(decoded, tx);
        assert!(decoded.is_contract_creation());
    }

    // --- EIP-7702 -----------------------------------------------------------

    #[test]
    fn eip7702_roundtrip() {
        let tx = EvmTx::Eip7702 {
            chain_id: 7777,
            nonce: 3,
            max_priority_fee_per_gas: u(1),
            max_fee_per_gas: u(200),
            gas_limit: 500_000,
            to: addr(0xee),
            value: u(0),
            data: vec![0xaa, 0xbb],
            access_list: vec![],
            authorization_list: vec![EvmAuthorization {
                chain_id: u(7777),
                address: addr(0xef),
                nonce: 0,
                y_parity: 1,
                r: U256::from(11u64),
                s: U256::from(22u64),
            }],
            y_parity: 0,
            r: U256::from(33u64),
            s: U256::from(44u64),
        };
        let bytes = tx.encode_ethereum_typed();
        assert_eq!(bytes[0], 0x04);
        let decoded = EvmTx::decode_ethereum_typed(&bytes).unwrap();
        assert_eq!(decoded, tx);
    }

    #[test]
    fn eip7702_requires_to() {
        // Construit un payload EIP-7702 avec `to` vide manuellement.
        use rlp::RlpStream;

        let mut s = RlpStream::new_list(13);
        s.append(&7777u64); // chain_id
        s.append(&0u64); // nonce
        s.append(&1u64); // max_priority_fee
        s.append(&1u64); // max_fee
        s.append(&21_000u64); // gas_limit
        s.append_empty_data(); // to = None  ← INVALIDE pour 7702
        s.append(&0u64); // value
        s.append_empty_data(); // data
        s.begin_list(0); // access_list
        s.begin_list(0); // authorization_list
        s.append(&0u8); // y_parity
        s.append(&1u64); // r
        s.append(&1u64); // s
        let mut bytes = vec![0x04u8];
        bytes.extend_from_slice(&s.out());

        let err = EvmTx::decode_ethereum_typed(&bytes).unwrap_err();
        assert_eq!(err, EvmTxError::MissingToForEip7702);
    }

    // --- Rejets -------------------------------------------------------------

    #[test]
    fn rejects_blob_4844_at_decode() {
        // Un payload de type 0x03 est rejeté, qu'il soit bien ou mal formé.
        let bytes = vec![0x03u8, 0xc0]; // 0x03 + RLP liste vide
        let err = EvmTx::decode_ethereum_typed(&bytes).unwrap_err();
        assert_eq!(err, EvmTxError::UnsupportedTxType { tx_type: 0x03 });
    }

    #[test]
    fn rejects_unknown_type() {
        let bytes = vec![0x05u8, 0xc0];
        assert!(matches!(
            EvmTx::decode_ethereum_typed(&bytes),
            Err(EvmTxError::UnsupportedTxType { .. })
        ));
    }

    #[test]
    fn rejects_empty_bytes() {
        assert_eq!(
            EvmTx::decode_ethereum_typed(&[]).unwrap_err(),
            EvmTxError::MalformedRlp
        );
    }

    #[test]
    fn rejects_legacy_v_too_low() {
        // Legacy avec v = 27 (pre-EIP-155) → rejet.
        use rlp::RlpStream;
        let mut s = RlpStream::new_list(9);
        s.append(&0u64); // nonce
        s.append(&1u64); // gas_price
        s.append(&21_000u64); // gas_limit
        {
            let to_addr = addr(0xaa);
            let a: &[u8] = to_addr.as_bytes();
            s.append(&a);
        }; // to
        s.append(&0u64); // value
        s.append_empty_data(); // data
        s.append(&27u64); // v = 27  ← pre-EIP-155, rejeté
        s.append(&1u64); // r
        s.append(&1u64); // s
        let mut bytes = vec![0x00u8];
        bytes.extend_from_slice(&s.out());

        let err = EvmTx::decode_ethereum_typed(&bytes).unwrap_err();
        assert!(matches!(err, EvmTxError::LegacyVTooLow(_)));
    }

    #[test]
    fn rejects_invalid_y_parity() {
        // EIP-2930 avec y_parity = 2.
        use rlp::RlpStream;
        let mut s = RlpStream::new_list(11);
        s.append(&1u64); // chain_id
        s.append(&0u64); // nonce
        s.append(&1u64); // gas_price
        s.append(&21_000u64); // gas_limit
        {
            let to_addr = addr(0xaa);
            let a: &[u8] = to_addr.as_bytes();
            s.append(&a);
        };
        s.append(&0u64); // value
        s.append_empty_data(); // data
        s.begin_list(0); // access_list
        s.append(&2u8); // y_parity = 2  ← invalide
        s.append(&1u64); // r
        s.append(&1u64); // s
        let mut bytes = vec![0x01u8];
        bytes.extend_from_slice(&s.out());

        let err = EvmTx::decode_ethereum_typed(&bytes).unwrap_err();
        assert_eq!(err, EvmTxError::InvalidYParity(2));
    }

    #[test]
    fn rejects_bad_storage_key_length() {
        // EIP-2930 avec une storage key de 20 bytes au lieu de 32.
        use rlp::RlpStream;
        let mut s = RlpStream::new_list(11);
        s.append(&1u64);
        s.append(&0u64);
        s.append(&1u64);
        s.append(&21_000u64);
        {
            let to_addr = addr(0xaa);
            let a: &[u8] = to_addr.as_bytes();
            s.append(&a);
        };
        s.append(&0u64);
        s.append_empty_data();
        // access_list : 1 item, storage_keys = [20 bytes]
        s.begin_list(1);
        s.begin_list(2);
        {
            let to_addr = addr(0xbb);
            let a: &[u8] = to_addr.as_bytes();
            s.append(&a);
        };
        s.begin_list(1);
        let bad_key: &[u8] = &[0x11u8; 20];
        s.append(&bad_key); // ← 20 bytes au lieu de 32
        s.append(&0u8);
        s.append(&1u64);
        s.append(&1u64);
        let mut bytes = vec![0x01u8];
        bytes.extend_from_slice(&s.out());

        let err = EvmTx::decode_ethereum_typed(&bytes).unwrap_err();
        assert!(matches!(err, EvmTxError::InvalidStorageKeyLength(20)));
    }

    // --- U256 max -----------------------------------------------------------

    #[test]
    fn handles_max_u256_value() {
        let max = U256::MAX;
        let tx = EvmTx::Eip1559 {
            chain_id: 1,
            nonce: u64::MAX,
            max_priority_fee_per_gas: max,
            max_fee_per_gas: max,
            gas_limit: u64::MAX,
            to: Some(addr(0xff)),
            value: max,
            data: vec![0xaa; 100],
            access_list: vec![],
            y_parity: 1,
            r: max,
            s: max,
        };
        let bytes = tx.encode_ethereum_typed();
        let decoded = EvmTx::decode_ethereum_typed(&bytes).unwrap();
        assert_eq!(decoded, tx);
    }

    // --- Discriminant check via accesseurs ----------------------------------

    #[test]
    fn accessors_work_across_variants() {
        let legacy = EvmTx::Legacy {
            chain_id: 1,
            nonce: 7,
            gas_price: u(1),
            gas_limit: 21_000,
            to: Some(addr(0xaa)),
            value: u(100),
            data: vec![],
            y_parity: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };
        assert_eq!(legacy.kind(), EvmTxKind::Legacy);
        assert_eq!(legacy.nonce(), 7);
        assert_eq!(legacy.gas_limit(), 21_000);
        assert_eq!(legacy.to(), Some(addr(0xaa)));
        assert_eq!(legacy.value(), u(100));
        assert!(!legacy.is_contract_creation());
    }
}
