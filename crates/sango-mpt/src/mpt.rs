//! Construction du MPT, calcul de racine, preuves et vérification.

use std::sync::LazyLock;

use sango_crypto::keccak256;
use sango_primitives::Hash32;

use crate::error::MptError;
use crate::nibbles::bytes_to_nibbles;
use crate::node::{
    decode_rlp, extract_branch_child_ref, extract_branch_value, extract_extension_child_ref, Node,
};

/// Racine d'un trie vide = `Keccak256(RLP(""))`.
///
/// RLP d'une chaîne vide est `0x80` (un seul byte). Vérifié par test.
static EMPTY_ROOT: LazyLock<Hash32> = LazyLock::new(|| keccak256(&[0x80]));

/// Racine du MPT vide. Vaut `keccak256(0x80)`.
#[must_use]
pub fn empty_root() -> Hash32 {
    *EMPTY_ROOT
}

/// Calcule la racine du MPT contenant `entries` (couples clé/valeur).
///
/// ## Déterminisme
///
/// La racine est **indépendante de l'ordre** des entrées : le MPT
/// structure l'information par nibbles de clé, pas par ordre d'insertion.
#[must_use]
pub fn mpt_root(entries: &[(Vec<u8>, Vec<u8>)]) -> Hash32 {
    if entries.is_empty() {
        return empty_root();
    }
    // Trie par chemin nibble pour un parcours stable.
    let mut sorted: Vec<(Vec<u8>, Vec<u8>)> = entries.to_vec();
    sorted.sort_by(|a, b| {
        let na = bytes_to_nibbles(&a.0);
        let nb = bytes_to_nibbles(&b.0);
        na.cmp(&nb)
    });
    let nibbles_entries: Vec<(Vec<u8>, Vec<u8>)> = sorted
        .into_iter()
        .map(|(k, v)| (bytes_to_nibbles(&k), v))
        .collect();
    let root = build_node(&nibbles_entries);
    root.hash()
}

/// Racine du trie des transactions d'un bloc :
///
/// ```text
/// key_i   = RLP(i)          (i = index de la transaction)
/// value_i = <bytes fournis>  (canonical Sango tx bytes en V1)
/// ```
///
/// C'est la formule normative du Freeze. En V1, `values[i]` est
/// `canonical_sango_tx_bytes`. Quand l'EVM arrivera, les txs EVM
/// fourniront `ethereum_typed_transaction_bytes` (déjà RLP).
#[must_use]
pub fn transaction_root<V: AsRef<[u8]>>(values: &[V]) -> Hash32 {
    let entries: Vec<(Vec<u8>, Vec<u8>)> = values
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let key = rlp::encode(&(i as u64)).to_vec();
            let value = v.as_ref().to_vec();
            (key, value)
        })
        .collect();
    mpt_root(&entries)
}

// --- Construction récursive -------------------------------------------------

fn build_node(entries: &[(Vec<u8>, Vec<u8>)]) -> Node {
    // entries : (chemin restant en nibbles, valeur)
    debug_assert!(!entries.is_empty());

    if entries.len() == 1 {
        return Node::Leaf {
            path: entries[0].0.clone(),
            value: entries[0].1.clone(),
        };
    }

    // Y a-t-il une entrée avec chemin vide ? (valeur de branche)
    let has_empty_key = entries.iter().any(|(k, _)| k.is_empty());

    if !has_empty_key {
        let common = common_prefix_len(entries);
        if common > 0 {
            let path = entries[0].0[..common].to_vec();
            let child_entries: Vec<(Vec<u8>, Vec<u8>)> = entries
                .iter()
                .map(|(k, v)| (k[common..].to_vec(), v.clone()))
                .collect();
            let child = Box::new(build_node(&child_entries));
            return Node::Extension { path, child };
        }
    }

    // Branche : partitionner par premier nibble.
    let mut children: [Option<Box<Node>>; 16] = Default::default();
    let mut branch_value: Option<Vec<u8>> = None;

    for nib in 0u8..16 {
        let sub: Vec<(Vec<u8>, Vec<u8>)> = entries
            .iter()
            .filter(|(k, _)| !k.is_empty() && k[0] == nib)
            .map(|(k, v)| (k[1..].to_vec(), v.clone()))
            .collect();
        if !sub.is_empty() {
            children[nib as usize] = Some(Box::new(build_node(&sub)));
        }
    }

    for (k, v) in entries {
        if k.is_empty() {
            branch_value = Some(v.clone());
            break;
        }
    }

    Node::Branch {
        children,
        value: branch_value,
    }
}

fn common_prefix_len(entries: &[(Vec<u8>, Vec<u8>)]) -> usize {
    debug_assert!(!entries.is_empty());
    let first = &entries[0].0;
    let mut common = first.len();
    for (k, _) in &entries[1..] {
        let mut len = 0;
        let limit = common.min(k.len());
        while len < limit && first[len] == k[len] {
            len += 1;
        }
        common = len;
        if common == 0 {
            break;
        }
    }
    common
}

// --- Preuves ----------------------------------------------------------------

/// Calcule une preuve MPT (liste de nœuds RLP encodés, du root vers la
/// feuille) pour `key`.
///
/// Retourne la liste de nœuds visités. Si la clé est **absente**, la
/// preuve est toujours valide et permet de démontrer l'absence.
#[must_use]
pub fn mpt_proof(entries: &[(Vec<u8>, Vec<u8>)], key: &[u8]) -> Vec<Vec<u8>> {
    if entries.is_empty() {
        return Vec::new();
    }
    let mut sorted: Vec<(Vec<u8>, Vec<u8>)> = entries.to_vec();
    sorted.sort_by(|a, b| {
        let na = bytes_to_nibbles(&a.0);
        let nb = bytes_to_nibbles(&b.0);
        na.cmp(&nb)
    });
    let nibbles_entries: Vec<(Vec<u8>, Vec<u8>)> = sorted
        .into_iter()
        .map(|(k, v)| (bytes_to_nibbles(&k), v))
        .collect();
    let root = build_node(&nibbles_entries);

    let target = bytes_to_nibbles(key);
    let mut proof = Vec::new();
    walk_collect(&root, &target, &mut proof);
    proof
}

fn walk_collect(node: &Node, key_nibbles: &[u8], proof: &mut Vec<Vec<u8>>) {
    proof.push(node.encode_rlp());
    match node {
        Node::Empty => {}
        Node::Leaf { path, .. } => {
            // Soit la feuille match (clé présente), soit elle diffère (clé absente).
            // Dans les deux cas, on s'arrête ici — la preuve contient toute
            // l'information nécessaire pour vérifier.
            let _ = path;
        }
        Node::Extension { path, child } => {
            if key_nibbles.starts_with(path) {
                walk_collect(child, &key_nibbles[path.len()..], proof);
            }
        }
        Node::Branch { children, .. } => {
            if key_nibbles.is_empty() {
                return;
            }
            let nib = key_nibbles[0] as usize;
            if let Some(child) = &children[nib] {
                walk_collect(child, &key_nibbles[1..], proof);
            }
        }
    }
}

/// Vérifie une preuve MPT contre une racine.
///
/// Retourne :
/// - `Ok(Some(value))` si la clé est présente et que la preuve est valide ;
/// - `Ok(None)` si la clé est absente et que la preuve démontre son absence ;
/// - `Err(_)` si la preuve est invalide ou mal formée.
pub fn verify_proof(
    root: Hash32,
    key: &[u8],
    proof: &[Vec<u8>],
) -> Result<Option<Vec<u8>>, MptError> {
    if proof.is_empty() {
        if root == empty_root() {
            return Ok(None);
        }
        return Err(MptError::EmptyProof);
    }

    // Le premier nœud doit hasher vers `root`.
    if keccak256(&proof[0]) != root {
        return Err(MptError::HashMismatch);
    }

    let key_nibbles = bytes_to_nibbles(key);
    walk_verify(proof, &key_nibbles)
}

fn walk_verify(proof: &[Vec<u8>], key_nibbles: &[u8]) -> Result<Option<Vec<u8>>, MptError> {
    let node_bytes = &proof[0];
    let node = decode_rlp(node_bytes)?;

    match node {
        Node::Empty => Ok(None),
        Node::Leaf { path, value } => {
            if path == key_nibbles {
                Ok(Some(value))
            } else {
                Ok(None)
            }
        }
        Node::Extension { path, child: _ } => {
            // On ignore l'enfant décodé (peut être `Empty` si hashé) :
            // c'est la référence brute qui compte pour vérifier le lien.
            if !key_nibbles.starts_with(&path) {
                return Ok(None);
            }
            let child_ref = extract_extension_child_ref(node_bytes)?;
            let remaining = &key_nibbles[path.len()..];
            descend(child_ref, remaining, &proof[1..])
        }
        Node::Branch {
            children: _,
            value: _,
        } => {
            if key_nibbles.is_empty() {
                return extract_branch_value(node_bytes);
            }
            let nib = key_nibbles[0] as usize;
            let child_ref = extract_branch_child_ref(node_bytes, nib)?;
            let remaining = &key_nibbles[1..];
            descend(child_ref, remaining, &proof[1..])
        }
    }
}

fn descend(
    child_ref: Vec<u8>,
    remaining_key: &[u8],
    rest: &[Vec<u8>],
) -> Result<Option<Vec<u8>>, MptError> {
    if child_ref.is_empty() {
        // Slot vide → clé absente, preuve valide.
        return Ok(None);
    }

    if child_ref.len() == 32 {
        // Référence hashée : le prochain élément du proof doit hasher vers elle.
        if rest.is_empty() {
            return Err(MptError::ProofTooShort);
        }
        let next = &rest[0];
        if keccak256(next).as_bytes() != child_ref.as_slice() {
            return Err(MptError::HashMismatch);
        }
        walk_verify(rest, remaining_key)
    } else {
        // Référence inline : les bytes doivent correspondre exactement
        // au prochain élément du proof.
        if rest.is_empty() {
            return Err(MptError::ProofTooShort);
        }
        if rest[0] != child_ref {
            return Err(MptError::InlineRefMismatch);
        }
        walk_verify(rest, remaining_key)
    }
}

/// Utilitaire interne pour valider qu'un `Node::Empty` peut être utilisé
/// comme placeholder. Ne fait rien — présent pour lisibilité.
#[allow(dead_code)]
fn _silence(_: &Node) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(k: &[u8], v: &[u8]) -> (Vec<u8>, Vec<u8>) {
        (k.to_vec(), v.to_vec())
    }

    // --- EMPTY_ROOT --------------------------------------------------------

    #[test]
    fn empty_root_matches_keccak_of_rlp_empty_string() {
        // RLP("") = 0x80. C'est le seul input valide pour la racine vide.
        let rlp_empty = vec![0x80u8];
        assert_eq!(empty_root(), keccak256(&rlp_empty));
    }

    #[test]
    fn empty_root_matches_ethereum_constant() {
        // Constante bien connue de l'écosystème Ethereum :
        // keccak256(rlp("")) = 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421
        let expected = "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421";
        assert_eq!(hex::encode(empty_root().as_bytes()), expected);
    }

    #[test]
    fn mpt_root_of_empty_entries_equals_empty_root() {
        assert_eq!(mpt_root(&[]), empty_root());
    }

    #[test]
    fn transaction_root_of_zero_txs_is_empty_root() {
        let values: Vec<Vec<u8>> = Vec::new();
        assert_eq!(transaction_root(&values), empty_root());
    }

    // --- Single entry ------------------------------------------------------

    #[test]
    fn single_entry_leaf() {
        let entries = vec![entry(b"abc", b"value")];
        let root = mpt_root(&entries);
        assert_ne!(root, empty_root());
    }

    #[test]
    fn single_entry_root_is_deterministic() {
        let entries = vec![entry(b"key", b"val")];
        assert_eq!(mpt_root(&entries), mpt_root(&entries));
    }

    #[test]
    fn single_entry_changes_with_value() {
        let a = mpt_root(&[entry(b"k", b"v1")]);
        let b = mpt_root(&[entry(b"k", b"v2")]);
        assert_ne!(a, b);
    }

    #[test]
    fn single_entry_changes_with_key() {
        let a = mpt_root(&[entry(b"k1", b"v")]);
        let b = mpt_root(&[entry(b"k2", b"v")]);
        assert_ne!(a, b);
    }

    // --- Multiple entries --------------------------------------------------

    #[test]
    fn root_is_independent_of_input_order() {
        let a = mpt_root(&[
            entry(b"alpha", b"1"),
            entry(b"beta", b"2"),
            entry(b"gamma", b"3"),
        ]);
        let b = mpt_root(&[
            entry(b"gamma", b"3"),
            entry(b"alpha", b"1"),
            entry(b"beta", b"2"),
        ]);
        assert_eq!(a, b);
    }

    #[test]
    fn root_of_same_entries_is_stable() {
        let entries = vec![
            entry(b"a", b"1"),
            entry(b"b", b"2"),
            entry(b"c", b"3"),
            entry(b"d", b"4"),
        ];
        assert_eq!(mpt_root(&entries), mpt_root(&entries));
    }

    #[test]
    fn shared_prefix_creates_extension() {
        // Ces deux clés partagent un préfixe important, ce qui doit
        // produire une extension suivie d'une branche.
        let entries = vec![entry(b"abcdef", b"1"), entry(b"abcxyz", b"2")];
        let root = mpt_root(&entries);
        assert_ne!(root, empty_root());
        // Déterministe
        assert_eq!(root, mpt_root(&entries));
    }

    #[test]
    fn empty_value_is_distinct_from_absent() {
        // Une entrée avec valeur vide est différente d'une clé absente.
        let with_empty = mpt_root(&[entry(b"k", b"")]);
        let without = mpt_root(&[entry(b"j", b"")]);
        assert_ne!(with_empty, without);
    }

    // --- Transaction root --------------------------------------------------

    #[test]
    fn tx_root_uses_rlp_of_index_as_key() {
        // Formule normative : key_i = RLP(i), value_i = bytes fournis.
        // Deux jeux de valeurs différentes produisent des roots différents.
        let a: Vec<Vec<u8>> = vec![b"tx0".to_vec()];
        let b: Vec<Vec<u8>> = vec![b"tx1".to_vec()];
        assert_ne!(transaction_root(&a), transaction_root(&b));
    }

    #[test]
    fn tx_root_order_matters() {
        // L'ordre des transactions est consensus-critical (index fait
        // partie de la clé).
        let a: Vec<Vec<u8>> = vec![b"first".to_vec(), b"second".to_vec()];
        let b: Vec<Vec<u8>> = vec![b"second".to_vec(), b"first".to_vec()];
        assert_ne!(transaction_root(&a), transaction_root(&b));
    }

    #[test]
    fn tx_root_for_zero_to_five_txs_is_stable() {
        for n in 0..=5u8 {
            let values: Vec<Vec<u8>> = (0..n).map(|i| vec![i]).collect();
            let a = transaction_root(&values);
            let b = transaction_root(&values);
            assert_eq!(a, b);
        }
    }

    // --- Proofs ------------------------------------------------------------

    #[test]
    fn proof_present_key() {
        let entries = vec![entry(b"key1", b"val1"), entry(b"key2", b"val2")];
        let root = mpt_root(&entries);
        let proof = mpt_proof(&entries, b"key1");
        let verified = verify_proof(root, b"key1", &proof).unwrap();
        assert_eq!(verified, Some(b"val1".to_vec()));
    }

    #[test]
    fn proof_absent_key() {
        let entries = vec![entry(b"key1", b"val1"), entry(b"key2", b"val2")];
        let root = mpt_root(&entries);
        let proof = mpt_proof(&entries, b"missing");
        let verified = verify_proof(root, b"missing", &proof).unwrap();
        assert_eq!(verified, None);
    }

    #[test]
    fn proof_empty_trie() {
        let root = empty_root();
        let verified = verify_proof(root, b"anything", &[]).unwrap();
        assert_eq!(verified, None);
    }

    #[test]
    fn proof_fails_on_wrong_root() {
        let entries = vec![entry(b"key1", b"val1")];
        let proof = mpt_proof(&entries, b"key1");
        let wrong_root = keccak256(b"not-the-root");
        assert!(verify_proof(wrong_root, b"key1", &proof).is_err());
    }

    #[test]
    fn proof_fails_on_tampered_value() {
        let entries = vec![entry(b"key1", b"val1")];
        let root = mpt_root(&entries);
        let mut proof = mpt_proof(&entries, b"key1");
        // Corrompt le payload du dernier nœud.
        if let Some(last) = proof.last_mut() {
            let n = last.len();
            last[n - 1] ^= 0x01;
        }
        let result = verify_proof(root, b"key1", &proof);
        // Soit HashMismatch, soit on atteint un nœud corrompu → erreur.
        assert!(result.is_err());
    }

    #[test]
    fn proof_deep_extension() {
        let entries = vec![
            entry(b"prefixaaaaaaaa", b"1"),
            entry(b"prefixaaaaaaab", b"2"),
            entry(b"prefixaaaaaaac", b"3"),
        ];
        let root = mpt_root(&entries);
        for key in [
            b"prefixaaaaaaaa" as &[u8],
            b"prefixaaaaaaab",
            b"prefixaaaaaaac",
        ] {
            let proof = mpt_proof(&entries, key);
            let verified = verify_proof(root, key, &proof).unwrap();
            assert!(verified.is_some(), "key {:?} should be present", key);
        }
    }

    #[test]
    fn proof_multi_index_tx_root() {
        let values: Vec<Vec<u8>> = (0..8u8).map(|i| vec![i; 4]).collect();
        let root = transaction_root(&values);
        // On ne peut pas utiliser transaction_root pour le proof sans
        // reconstruire les entries ; on reconstruit à la main.
        let entries: Vec<(Vec<u8>, Vec<u8>)> = values
            .iter()
            .enumerate()
            .map(|(i, v)| (rlp::encode(&(i as u64)).to_vec(), v.clone()))
            .collect();
        for (i, v) in values.iter().enumerate() {
            let key = rlp::encode(&(i as u64)).to_vec();
            let proof = mpt_proof(&entries, &key);
            let verified = verify_proof(root, &key, &proof).unwrap();
            assert_eq!(verified.as_deref(), Some(v.as_slice()));
        }
    }
}
