//! Bridge entre [`EvmState`] et `revm 42.0.1`.
//!
//! ## Rôle
//!
//! Fournir une implémentation de `revm::Database` et
//! `revm::DatabaseCommit` qui lit/écrit dans un [`EvmState`]. Le bridge
//! est **isolé** : il ne touche ni au consensus, ni au `BlockHeader`, ni
//! aux roots.
//!
//! ## `prevrandao`
//!
//! Valeur **normative**, dérivée du parent :
//!
//! ```text
//! prevrandao = Keccak256("SANGO/EVM/PREVRANDAO/V1" || parent_block_hash)
//! ```
//!
//! Le bridge **ne dérive pas** cette valeur : il la reçoit dans
//! [`EvmBlockEnv`]. La dérivation est du ressort de `sango-exec`.

use alloy_eip2930::{AccessList, AccessListItem};
use alloy_primitives::map::{FbBuildHasher, HashMap};
// Alias local : revm 42 exige `FbBuildHasher<20>` pour `commit`.
type RevmHashMap<K, V> = HashMap<K, V, FbBuildHasher<20>>;

use revm::context::{
    result::{ExecutionResult, Output},
    BlockEnv, CfgEnv, TxEnv,
};
use revm::database::{Database, DatabaseCommit};
use revm::database_interface::DBErrorMarker;
use revm::primitives::{hardfork::SpecId, Address as RevmAddress, TxKind, B256, U256 as RevmU256};
use revm::state::{Account, AccountInfo};
use revm::{Context, ExecuteEvm, MainBuilder, MainContext};

use sango_crypto::keccak256;
use sango_primitives::{EvmAddress, Hash32, U256};
use sango_types::{EvmAccount, EvmLog};

use crate::error::EvmError;
use crate::state::EvmState;

// --- Conversions ------------------------------------------------------------

/// `sango_primitives::EvmAddress` → `revm::primitives::Address`.
///
/// Conversion **byte-à-byte**, aucune transformation cryptographique.
#[must_use]
pub fn to_revm_address(addr: &EvmAddress) -> RevmAddress {
    RevmAddress::from_slice(addr.as_bytes())
}

/// `revm::primitives::Address` → `sango_primitives::EvmAddress`.
#[must_use]
pub fn from_revm_address(addr: &RevmAddress) -> EvmAddress {
    EvmAddress::from_bytes(addr.0 .0)
}

/// `Hash32` → `B256`.
#[must_use]
pub fn to_b256(h: &Hash32) -> B256 {
    B256::from_slice(h.as_bytes())
}

/// `B256` → `Hash32`.
#[must_use]
pub fn from_b256(h: &B256) -> Hash32 {
    Hash32::from_bytes(h.0)
}

// --- Contexte de bloc -------------------------------------------------------

/// Contexte de bloc passé à revm.
///
/// Dérivé du `BlockHeader` par l'appelant (`sango-exec` en 4c.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvmBlockEnv {
    /// Chain ID EVM.
    pub chain_id: u64,
    /// Hauteur du bloc.
    pub number: u64,
    /// Timestamp Unix du bloc.
    pub timestamp: u64,
    /// Plafond de gas du bloc.
    pub gas_limit: u64,
    /// Base fee courante (EIP-1559).
    pub base_fee: U256,
    /// Adresse du proposeur (coinbase).
    pub coinbase: EvmAddress,
    /// `prevrandao` — déterministe, dérivé du parent.
    pub prevrandao: Hash32,
    /// Hash du bloc à `number - 1`, pour `BLOCKHASH`.
    pub parent_block_hash: Hash32,
}

// --- Résultat d'exécution ---------------------------------------------------

/// Résultat d'exécution d'une transaction EVM.
///
/// **Aucun receipt n'est produit ici** — `sango-exec` combine ce résultat
/// avec `AppliedTransaction` pour produire un `Receipt` unique.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvmOutcome {
    /// Succès ou échec.
    pub success: bool,
    /// Gas consommé total.
    pub gas_used: u64,
    /// Logs émis par l'exécution.
    pub logs: Vec<EvmLog>,
    /// Adresse du contrat créé (si `ContractCreate`).
    pub contract_address: Option<EvmAddress>,
    /// Données de retour (call uniquement, succès).
    pub output: Vec<u8>,
}

// --- EvmDb ------------------------------------------------------------------

/// Vue `Database` + `DatabaseCommit` sur un [`EvmState`].
pub struct EvmDb<'a> {
    state: &'a mut EvmState,
    parent_block_hash: B256,
}

impl<'a> EvmDb<'a> {
    /// Construit une vue.
    #[must_use]
    pub fn new(state: &'a mut EvmState, parent_block_hash: Hash32) -> Self {
        Self {
            state,
            parent_block_hash: to_b256(&parent_block_hash),
        }
    }
}

// --- Database impl ----------------------------------------------------------

impl Database for EvmDb<'_> {
    type Error = EvmError;

    fn basic(&mut self, address: RevmAddress) -> Result<Option<AccountInfo>, Self::Error> {
        let sango_addr = from_revm_address(&address);
        Ok(self.state.get_account(&sango_addr).map(account_to_info))
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<revm::bytecode::Bytecode, Self::Error> {
        let h = from_b256(&code_hash);
        // Un `code_hash` vide (keccak256(&[])) → bytecode vide.
        if h == sango_types::empty_code_hash() {
            return Ok(revm::bytecode::Bytecode::default());
        }
        let bytes = self.state.get_code(&h)?;
        Ok(revm::bytecode::Bytecode::new_raw(bytes.to_vec().into()))
    }

    fn storage(&mut self, address: RevmAddress, index: RevmU256) -> Result<RevmU256, Self::Error> {
        let sango_addr = from_revm_address(&address);
        // U256 identiques (`ruint::Uint<256, 4>`) — aucune conversion.
        Ok(self.state.get_storage(&sango_addr, index))
    }

    fn block_hash(&mut self, _number: u64) -> Result<B256, Self::Error> {
        // En V1, seul le parent est disponible. Les autres hauteurs
        // retournent zéro (comportement Ethereum : bloc hors fenêtre → 0).
        // En 4c.3, une colonne `Blocks` fournira l'historique complet.
        Ok(self.parent_block_hash)
    }
}

// --- DatabaseCommit impl ----------------------------------------------------

impl DatabaseCommit for EvmDb<'_> {
    fn commit(&mut self, changes: RevmHashMap<RevmAddress, Account>) {
        for (revm_addr, account) in changes {
            let sango_addr = from_revm_address(&revm_addr);

            // 1. Storage d'abord : `set_storage` recalcule le storage_root
            //    du compte propriétaire.
            for (slot, storage_slot) in account.storage {
                self.state
                    .set_storage(sango_addr, slot, storage_slot.present_value);
            }

            // 2. Ensuite les autres champs du compte, en préservant le
            //    storage_root qui vient d'être calculé.
            let storage_root = self.state.storage_root(&sango_addr);
            let code_hash = from_b256(&account.info.code_hash);

            // 3. Code : si revm fournit le bytecode, on l'ajoute au state.
            //    `put_code` vérifie `Keccak256(bytecode) == code_hash`.
            if let Some(ref code) = account.info.code {
                let bytes = code.original_bytes().to_vec();
                if keccak256(&bytes) == code_hash {
                    let _ = self.state.put_code(code_hash, bytes);
                }
            }

            // 4. Le compte : reconstruit avec le storage_root recalculé.
            let sango_account = EvmAccount {
                nonce: account.info.nonce,
                balance: account.info.balance,
                storage_root,
                code_hash,
            };
            self.state.set_account(sango_addr, sango_account);
        }
    }
}

// --- DBErrorMarker impl -----------------------------------------------------

impl DBErrorMarker for EvmError {}

// --- Helpers ----------------------------------------------------------------

fn account_to_info(acc: EvmAccount) -> AccountInfo {
    AccountInfo {
        balance: acc.balance,
        nonce: acc.nonce,
        code_hash: to_b256(&acc.code_hash),
        // Le code est demandé séparément par revm via `code_by_hash`.
        code: None,
        account_id: None,
    }
}

// --- TxEnvExtras ------------------------------------------------------------

/// Champs hors `EvmTx` nécessaires à la construction d'un `TxEnv` revm.
///
/// Contient notamment `caller` (adresse de l'émetteur, dérivée de la
/// signature secp256k1 côté `sango-exec`) et le prix effectif calculé par
/// la règle Sango (`sango-exec::evm_fee`).
#[derive(Clone, Debug)]
pub struct TxEnvExtras {
    /// Adresse EVM de l'émetteur.
    pub caller: EvmAddress,
    /// Prix effectif par unité de gas, calculé par `sango-exec` :
    ///
    /// ```text
    /// effective_gas_price = min(max_fee, base_fee + priority_fee)
    /// ```
    pub effective_gas_price: U256,
}

// --- Exécution --------------------------------------------------------------

/// Exécute une transaction EVM contre un [`EvmState`] mutable.
///
/// ## Contrat
///
/// 1. État initial lu via [`EvmDb`] (`Database`).
/// 2. `TxEnv` revm 42 construit depuis `EvmTx` + `TxEnvExtras`.
/// 3. Exécution avec `SpecId::PRAGUE`.
/// 4. Mutations **commitées** dans `state` via `DatabaseCommit`.
/// 5. `state.state_root()` (appelé par l'appelant **après** retour) reflète
///    les mutations.
///
/// ## Note U256
///
/// `sango_primitives::U256` et `revm::primitives::U256` sont **le même
/// type** (`ruint::Uint<256, 4>`). Aucune conversion numérique, sauf pour
/// les champs `u128` / `u64` (gas_price, basefee) où on sature.
pub fn evm_transact(
    state: &mut EvmState,
    tx: &sango_types::EvmTx,
    block: &EvmBlockEnv,
    extras: TxEnvExtras,
) -> Result<EvmOutcome, EvmError> {
    let tx_env = build_tx_env(tx, &extras)?;
    let block_env = build_block_env(block);
    let cfg_env = build_cfg_env(block);

    let mut db = EvmDb::new(state, block.parent_block_hash);

    let mut evm = Context::mainnet()
        .with_db(&mut db)
        .with_cfg(cfg_env)
        .with_block(block_env)
        .build_mainnet();

    let result = evm
        .transact(tx_env)
        .map_err(|e| EvmError::Revm(format!("{e:?}")))?;

    // Commit dans EvmState.
    db.commit(result.state);

    Ok(format_result(result.result))
}

// --- Construction des environnements revm ----------------------------------

fn build_block_env(block: &EvmBlockEnv) -> BlockEnv {
    BlockEnv {
        number: RevmU256::from(block.number),
        beneficiary: to_revm_address(&block.coinbase),
        timestamp: RevmU256::from(block.timestamp),
        gas_limit: block.gas_limit,
        // `basefee: u64` dans revm 42.
        basefee: u256_to_u64_saturating(block.base_fee),
        difficulty: RevmU256::ZERO,
        prevrandao: Some(to_b256(&block.prevrandao)),
        ..Default::default()
    }
}

// `CfgEnv` est `#[non_exhaustive]` dans revm 42 : struct literal interdit,
// on doit passer par l'assignation champ par champ.
#[allow(clippy::field_reassign_with_default)]
fn build_cfg_env(block: &EvmBlockEnv) -> CfgEnv {
    let mut c = CfgEnv::default();
    c.chain_id = block.chain_id;
    c.spec = SpecId::PRAGUE;
    c
}

fn build_tx_env(tx: &sango_types::EvmTx, extras: &TxEnvExtras) -> Result<TxEnv, EvmError> {
    use sango_types::EvmTx;

    let caller = to_revm_address(&extras.caller);
    let gas_limit = tx.gas_limit();
    let value = tx.value();
    let data = tx.data().to_vec();
    let nonce = tx.nonce();

    let kind = match tx {
        EvmTx::Legacy { to, .. } | EvmTx::Eip2930 { to, .. } | EvmTx::Eip1559 { to, .. } => {
            match to {
                Some(a) => TxKind::Call(to_revm_address(a)),
                None => TxKind::Create,
            }
        }
        EvmTx::Eip7702 { to, .. } => TxKind::Call(to_revm_address(to)),
    };

    // `gas_price` : `u128` dans revm 42.
    //
    // - Legacy / EIP-2930 : `gas_price = gas_price`, pas de priority fee.
    // - EIP-1559 / EIP-7702 : `gas_price = max_fee_per_gas`,
    //   `gas_priority_fee = Some(max_priority_fee_per_gas)`.
    let (gas_price, gas_priority_fee, tx_type, access_list, blob_hashes) = match tx {
        EvmTx::Legacy { gas_price, .. } => (
            u256_to_u128_saturating(*gas_price),
            None,
            0u8,
            AccessList::default(),
            Vec::new(),
        ),
        EvmTx::Eip2930 {
            gas_price,
            access_list,
            ..
        } => (
            u256_to_u128_saturating(*gas_price),
            None,
            1u8,
            access_list_to_revm(access_list),
            Vec::new(),
        ),
        EvmTx::Eip1559 {
            max_fee_per_gas,
            max_priority_fee_per_gas,
            access_list,
            ..
        } => (
            u256_to_u128_saturating(*max_fee_per_gas),
            Some(u256_to_u128_saturating(*max_priority_fee_per_gas)),
            2u8,
            access_list_to_revm(access_list),
            Vec::new(),
        ),
        EvmTx::Eip7702 {
            max_fee_per_gas,
            max_priority_fee_per_gas,
            access_list,
            ..
        } => (
            u256_to_u128_saturating(*max_fee_per_gas),
            Some(u256_to_u128_saturating(*max_priority_fee_per_gas)),
            4u8,
            access_list_to_revm(access_list),
            Vec::new(),
        ),
    };

    // `authorization_list` reste vide en V1 (EIP-7702 accepté au décodage
    // mais l'exécution réelle sera branchée en 4c.3).
    Ok(TxEnv {
        tx_type,
        caller,
        gas_limit,
        gas_price,
        gas_priority_fee,
        kind,
        value,
        data: data.into(),
        nonce,
        chain_id: Some(chain_id_of(tx)),
        access_list,
        blob_hashes,
        ..Default::default()
    })
}

fn chain_id_of(tx: &sango_types::EvmTx) -> u64 {
    use sango_types::EvmTx;
    match tx {
        EvmTx::Legacy { chain_id, .. }
        | EvmTx::Eip2930 { chain_id, .. }
        | EvmTx::Eip1559 { chain_id, .. }
        | EvmTx::Eip7702 { chain_id, .. } => *chain_id,
    }
}

fn access_list_to_revm(list: &sango_types::EvmAccessList) -> AccessList {
    let entries: Vec<AccessListItem> = list
        .iter()
        .map(|item| AccessListItem {
            address: to_revm_address(&item.address),
            storage_keys: item.storage_keys.iter().map(to_b256).collect(),
        })
        .collect();
    AccessList(entries)
}

fn u256_to_u128_saturating(v: U256) -> u128 {
    if v > U256::from(u128::MAX) {
        u128::MAX
    } else {
        v.to::<u128>()
    }
}

fn u256_to_u64_saturating(v: U256) -> u64 {
    if v > U256::from(u64::MAX) {
        u64::MAX
    } else {
        v.to::<u64>()
    }
}

// --- Formatage du résultat revm ---------------------------------------------

fn format_result(result: ExecutionResult) -> EvmOutcome {
    match result {
        ExecutionResult::Success {
            reason: _,
            gas,
            output,
            logs,
            ..
        } => {
            let (contract_address, output_bytes) = match output {
                Output::Create(_, addr_opt) => {
                    (addr_opt.map(|a| from_revm_address(&a)), Vec::new())
                }
                Output::Call(bytes) => (None, bytes.to_vec()),
            };
            EvmOutcome {
                success: true,
                gas_used: gas.tx_gas_used(),
                logs: logs
                    .into_iter()
                    .map(|l| EvmLog {
                        address: from_revm_address(&l.address),
                        topics: l.data.topics().iter().map(from_b256).collect(),
                        data: l.data.data.to_vec(),
                    })
                    .collect(),
                contract_address,
                output: output_bytes,
            }
        }
        ExecutionResult::Revert { gas, output, .. } => EvmOutcome {
            success: false,
            gas_used: gas.tx_gas_used(),
            logs: Vec::new(),
            contract_address: None,
            output: output.to_vec(),
        },
        ExecutionResult::Halt { reason: _, gas, .. } => EvmOutcome {
            success: false,
            gas_used: gas.tx_gas_used(),
            logs: Vec::new(),
            contract_address: None,
            output: Vec::new(),
        },
    }
}

// --- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use revm::state::{EvmStorageSlot as StorageSlot, TransactionId};
    use sango_types::empty_code_hash;

    fn addr(b: u8) -> EvmAddress {
        EvmAddress::from_bytes([b; 20])
    }

    fn make_account(nonce: u64, balance: u64) -> EvmAccount {
        EvmAccount {
            nonce,
            balance: U256::from(balance),
            storage_root: sango_mpt::empty_root(),
            code_hash: empty_code_hash(),
        }
    }

    fn sample_block() -> EvmBlockEnv {
        EvmBlockEnv {
            chain_id: 7777,
            number: 1,
            timestamp: 1_700_000_000,
            gas_limit: 30_000_000,
            base_fee: U256::from(1),
            coinbase: addr(0xef),
            prevrandao: Hash32::from_bytes([0x42; 32]),
            parent_block_hash: Hash32::from_bytes([0x01; 32]),
        }
    }

    // --- Helpers ----------------------------------------------------------

    /// Construit un **init code** qui déploie `runtime` comme contrat.
    ///
    /// Format :
    ///
    /// ```text
    /// PUSH1 <len>           // 0x60 <len>
    /// PUSH1 <preamble_len>  // 0x60 0x0c
    /// PUSH1 0               // 0x60 0x00
    /// CODECOPY              // 0x39
    /// PUSH1 <len>           // 0x60 <len>
    /// PUSH1 0               // 0x60 0x00
    /// RETURN                // 0xf3
    /// <runtime>
    /// ```
    ///
    /// `CODECOPY` copie `len` bytes depuis l'offset `preamble_len` du
    /// **code** (où commence le runtime) vers la mémoire à l'adresse 0.
    /// `RETURN` retourne ces `len` bytes.
    fn init_code_for_runtime(runtime: &[u8]) -> Vec<u8> {
        assert!(runtime.len() <= 0xFF, "runtime > 255 bytes non supporté");
        let len = runtime.len() as u8;
        let preamble_len: u8 = 12;
        let mut code = Vec::with_capacity(preamble_len as usize + runtime.len());
        code.extend_from_slice(&[0x60, len]); // PUSH1 len
        code.extend_from_slice(&[0x60, preamble_len]); // PUSH1 offset
        code.extend_from_slice(&[0x60, 0x00]); // PUSH1 0
        code.push(0x39); // CODECOPY
        code.extend_from_slice(&[0x60, len]); // PUSH1 len
        code.extend_from_slice(&[0x60, 0x00]); // PUSH1 0
        code.push(0xf3); // RETURN
        code.extend_from_slice(runtime);
        code
    }

    // --- Conversions ------------------------------------------------------

    #[test]
    fn address_conversion_roundtrip() {
        let a = addr(0xaa);
        let r = to_revm_address(&a);
        let back = from_revm_address(&r);
        assert_eq!(a, back);
    }

    #[test]
    fn b256_conversion_roundtrip() {
        let h = Hash32::from_bytes([0x42; 32]);
        let b = to_b256(&h);
        let back = from_b256(&b);
        assert_eq!(h, back);
    }

    #[test]
    fn u256_is_shared_type() {
        // Compile-only : si ce test compile, `sango_primitives::U256` et
        // `revm::primitives::U256` sont **le même type**.
        let sango_val: U256 = U256::from(42u64);
        let revm_val: RevmU256 = sango_val;
        assert_eq!(revm_val, RevmU256::from(42u64));
    }

    // --- Database : basic -------------------------------------------------

    #[test]
    fn database_basic_existing_account() {
        let mut state = EvmState::new();
        let a = addr(0xaa);
        state.set_account(a, make_account(3, 1000));

        let mut db = EvmDb::new(&mut state, Hash32::ZERO);
        let info = db.basic(to_revm_address(&a)).unwrap().unwrap();
        assert_eq!(info.nonce, 3);
        assert_eq!(info.balance, RevmU256::from(1000u64));
        assert_eq!(info.code_hash, to_b256(&empty_code_hash()));
    }

    #[test]
    fn database_basic_missing_account() {
        let mut state = EvmState::new();
        let mut db = EvmDb::new(&mut state, Hash32::ZERO);
        let info = db.basic(to_revm_address(&addr(0xaa))).unwrap();
        assert!(info.is_none());
    }

    // --- Database : storage -----------------------------------------------

    #[test]
    fn database_storage_read() {
        let mut state = EvmState::new();
        let a = addr(0xaa);
        state.set_storage(a, RevmU256::from(1u64), RevmU256::from(42u64));

        let mut db = EvmDb::new(&mut state, Hash32::ZERO);
        let v = db
            .storage(to_revm_address(&a), RevmU256::from(1u64))
            .unwrap();
        assert_eq!(v, RevmU256::from(42u64));
    }

    #[test]
    fn database_storage_write() {
        let mut state = EvmState::new();
        let a = addr(0xaa);
        state.set_account(a, make_account(0, 0));

        let mut db = EvmDb::new(&mut state, Hash32::ZERO);
        let mut account = Account::from(AccountInfo {
            balance: RevmU256::ZERO,
            nonce: 0,
            code_hash: to_b256(&empty_code_hash()),
            code: None,
            account_id: None,
        });
        account.storage.insert(
            RevmU256::from(1u64),
            StorageSlot::new(RevmU256::from(42u64), TransactionId::default()),
        );
        let mut changes = RevmHashMap::default();
        changes.insert(to_revm_address(&a), account);
        db.commit(changes);

        assert_eq!(
            state.get_storage(&a, RevmU256::from(1u64)),
            RevmU256::from(42u64)
        );
    }

    // --- Database : code --------------------------------------------------

    #[test]
    fn database_code_by_hash() {
        let mut state = EvmState::new();
        let bytecode = vec![0x60, 0x01, 0x60, 0x02];
        let code_hash = keccak256(&bytecode);
        state.put_code(code_hash, bytecode.clone()).unwrap();

        let mut db = EvmDb::new(&mut state, Hash32::ZERO);
        let code = db.code_by_hash(to_b256(&code_hash)).unwrap();
        assert_eq!(code.original_bytes().to_vec(), bytecode);
    }

    #[test]
    fn database_code_by_hash_empty_hash_returns_default() {
        let mut state = EvmState::new();
        let mut db = EvmDb::new(&mut state, Hash32::ZERO);
        let code = db.code_by_hash(to_b256(&empty_code_hash())).unwrap();
        assert_eq!(code.original_bytes().to_vec(), Vec::<u8>::new());
    }

    #[test]
    fn code_hash_mismatch_rejected_by_state() {
        let mut state = EvmState::new();
        let bytecode = vec![0xffu8; 10];
        let fake_hash = Hash32::from_bytes([0xab; 32]);
        let err = state.restore_code_entry(fake_hash, bytecode).unwrap_err();
        assert!(matches!(err, EvmError::CodeHashMismatch { .. }));
    }

    // --- Database : block_hash --------------------------------------------

    #[test]
    fn database_block_hash() {
        let parent = Hash32::from_bytes([0xaa; 32]);
        let mut state = EvmState::new();
        let mut db = EvmDb::new(&mut state, parent);
        let h = db.block_hash(0).unwrap();
        assert_eq!(h, to_b256(&parent));
    }

    // --- DatabaseCommit ---------------------------------------------------

    #[test]
    fn database_commit_account() {
        let mut state = EvmState::new();
        let a = addr(0xaa);
        state.set_account(a, make_account(0, 0));

        let mut db = EvmDb::new(&mut state, Hash32::ZERO);
        let account = Account::from(AccountInfo {
            balance: RevmU256::from(5000u64),
            nonce: 7,
            code_hash: to_b256(&empty_code_hash()),
            code: None,
            account_id: None,
        });
        let mut changes = RevmHashMap::default();
        changes.insert(to_revm_address(&a), account);
        db.commit(changes);

        let acc = state.get_account(&a).unwrap();
        assert_eq!(acc.nonce, 7);
        assert_eq!(acc.balance, U256::from(5000u64));
    }

    #[test]
    fn database_commit_storage() {
        let mut state = EvmState::new();
        let a = addr(0xaa);
        state.set_account(a, make_account(1, 100));

        let mut db = EvmDb::new(&mut state, Hash32::ZERO);
        let mut account = Account::from(AccountInfo {
            balance: RevmU256::from(100u64),
            nonce: 1,
            code_hash: to_b256(&empty_code_hash()),
            code: None,
            account_id: None,
        });
        account.storage.insert(
            RevmU256::from(7u64),
            StorageSlot::new(RevmU256::from(999u64), TransactionId::default()),
        );
        let mut changes = RevmHashMap::default();
        changes.insert(to_revm_address(&a), account);
        db.commit(changes);

        assert_eq!(
            state.get_storage(&a, RevmU256::from(7u64)),
            RevmU256::from(999u64)
        );
        assert_ne!(
            state.get_account(&a).unwrap().storage_root,
            sango_mpt::empty_root()
        );
    }

    // --- Exécution EVM ----------------------------------------------------

    #[test]
    fn transfer_execution() {
        let mut state = EvmState::new();
        let from = addr(0x01);
        let to = addr(0x02);
        state.set_account(from, make_account(0, 1_000_000));
        state.set_account(to, make_account(0, 0));

        let tx = sango_types::EvmTx::Legacy {
            chain_id: 7777,
            nonce: 0,
            gas_price: U256::from(1u64),
            gas_limit: 21_000,
            to: Some(to),
            value: U256::from(100u64),
            data: vec![],
            y_parity: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };

        let extras = TxEnvExtras {
            caller: from,
            effective_gas_price: U256::from(1u64),
        };

        let outcome = evm_transact(&mut state, &tx, &sample_block(), extras).unwrap();
        assert!(outcome.success);
        assert_eq!(state.get_account(&to).unwrap().balance, U256::from(100u64));
        assert_eq!(state.get_account(&from).unwrap().nonce, 1);
    }

    #[test]
    fn contract_create() {
        // Runtime qui retourne 32 bytes valant 0x…01 :
        //   PUSH1 1, PUSH1 0, MSTORE, PUSH1 32, PUSH1 0, RETURN
        let runtime = vec![0x60, 0x01, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];
        let init_code = init_code_for_runtime(&runtime);

        let mut state = EvmState::new();
        let from = addr(0x01);
        state.set_account(from, make_account(0, 10_000_000));

        let tx = sango_types::EvmTx::Legacy {
            chain_id: 7777,
            nonce: 0,
            gas_price: U256::from(1u64),
            gas_limit: 200_000,
            to: None,
            value: U256::ZERO,
            data: init_code,
            y_parity: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };

        let extras = TxEnvExtras {
            caller: from,
            effective_gas_price: U256::from(1u64),
        };

        let outcome = evm_transact(&mut state, &tx, &sample_block(), extras).unwrap();
        assert!(outcome.success);
        let contract = outcome.contract_address.expect("contrat créé");
        let acc = state.get_account(&contract).expect("compte contrat");
        assert_ne!(acc.code_hash, empty_code_hash());
        // Le runtime déployé est exactement `runtime`.
        let deployed = state.get_code(&acc.code_hash).expect("code déployé");
        assert_eq!(deployed, runtime.as_slice());
    }

    #[test]
    fn contract_call() {
        // Runtime qui retourne 32 bytes valant 0x…01.
        let runtime = vec![0x60, 0x01, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];
        let init_code = init_code_for_runtime(&runtime);

        let mut state = EvmState::new();
        let from = addr(0x01);
        state.set_account(from, make_account(0, 10_000_000));

        let create_tx = sango_types::EvmTx::Legacy {
            chain_id: 7777,
            nonce: 0,
            gas_price: U256::from(1u64),
            gas_limit: 200_000,
            to: None,
            value: U256::ZERO,
            data: init_code,
            y_parity: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };
        let extras = TxEnvExtras {
            caller: from,
            effective_gas_price: U256::from(1u64),
        };
        let created =
            evm_transact(&mut state, &create_tx, &sample_block(), extras.clone()).unwrap();
        let contract = created.contract_address.unwrap();

        let call_tx = sango_types::EvmTx::Legacy {
            chain_id: 7777,
            nonce: 1,
            gas_price: U256::from(1u64),
            gas_limit: 50_000,
            to: Some(contract),
            value: U256::ZERO,
            data: vec![],
            y_parity: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };
        let outcome = evm_transact(&mut state, &call_tx, &sample_block(), extras).unwrap();
        assert!(outcome.success);
        // Le runtime retourne 32 bytes valant 0x…01.
        assert_eq!(outcome.output.len(), 32);
        assert_eq!(outcome.output[31], 1);
    }

    #[test]
    fn transfer_nonce_increments() {
        let mut state = EvmState::new();
        let from = addr(0x01);
        let to = addr(0x02);
        state.set_account(from, make_account(0, 1_000_000));

        let extras = TxEnvExtras {
            caller: from,
            effective_gas_price: U256::from(1u64),
        };

        let tx0 = sango_types::EvmTx::Legacy {
            chain_id: 7777,
            nonce: 0,
            gas_price: U256::from(1u64),
            gas_limit: 21_000,
            to: Some(to),
            value: U256::from(100u64),
            data: vec![],
            y_parity: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };
        evm_transact(&mut state, &tx0, &sample_block(), extras.clone()).unwrap();

        let tx1 = sango_types::EvmTx::Legacy {
            chain_id: 7777,
            nonce: 1,
            gas_price: U256::from(1u64),
            gas_limit: 21_000,
            to: Some(to),
            value: U256::from(200u64),
            data: vec![],
            y_parity: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };
        evm_transact(&mut state, &tx1, &sample_block(), extras).unwrap();

        assert_eq!(state.get_account(&to).unwrap().balance, U256::from(300u64));
        assert_eq!(state.get_account(&from).unwrap().nonce, 2);
    }
}
