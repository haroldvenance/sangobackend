//! Nœuds du MPT (structure + encodage RLP).

use rlp::RlpStream;
use sango_crypto::keccak256;
use sango_primitives::Hash32;

use crate::error::MptError;
use crate::nibbles::{from_hex_prefix, hex_prefix};

/// Un nœud du MPT.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Node {
    /// Nœud vide (RLP `0x80`).
    Empty,
    /// Feuille : chemin restant (nibbles) + valeur.
    Leaf {
        /// Chemin restant en nibbles.
        path: Vec<u8>,
        /// Valeur associée à la clé complète.
        value: Vec<u8>,
    },
    /// Extension : chemin partagé (nibbles) + enfant unique.
    Extension {
        /// Chemin partagé en nibbles.
        path: Vec<u8>,
        /// Sous-arbre enfant (inline ou référencé par hash).
        child: Box<Node>,
    },
    /// Branche : 16 enfants (par nibble) + valeur optionnelle (si un
    /// chemin se termine exactement à cette branche).
    Branch {
        /// Enfants indexés par nibble (0x0 à 0xf). `None` = slot vide.
        children: [Option<Box<Node>>; 16],
        /// Valeur associée au chemin qui se termine ici (`None` = pas de
        /// valeur à cette position).
        value: Option<Vec<u8>>,
    },
}

impl Node {
    /// Encode le nœud en RLP (Ethereum-compatible).
    #[must_use]
    pub fn encode_rlp(&self) -> Vec<u8> {
        match self {
            Node::Empty => {
                let mut s = RlpStream::new();
                s.append_empty_data();
                s.out().to_vec()
            }
            Node::Leaf { path, value } => {
                let hp = hex_prefix(path, true);
                let mut s = RlpStream::new_list(2);
                s.append(&hp);
                s.append(value);
                s.out().to_vec()
            }
            Node::Extension { path, child } => {
                let hp = hex_prefix(path, false);
                let mut s = RlpStream::new_list(2);
                s.append(&hp);
                child.append_reference_to(&mut s);
                s.out().to_vec()
            }
            Node::Branch { children, value } => {
                let mut s = RlpStream::new_list(17);
                for c in children {
                    match c {
                        Some(child) => {
                            child.append_reference_to(&mut s);
                        }
                        None => {
                            s.append_empty_data();
                        }
                    }
                }
                match value {
                    Some(v) => {
                        s.append(v);
                    }
                    None => {
                        s.append_empty_data();
                    }
                }
                s.out().to_vec()
            }
        }
    }

    /// Écrit la référence de ce nœud dans `s`, conforme à la règle des
    /// 32 bytes d'Ethereum :
    ///
    /// - si l'encodage RLP fait **strictement moins de 32 bytes** :
    ///   injecter les bytes RLP **tels quels** (référence inline) ;
    /// - sinon : écrire `Keccak256(encodage)` comme byte string RLP
    ///   (32 bytes).
    pub fn append_reference_to(&self, s: &mut RlpStream) {
        let enc = self.encode_rlp();
        if enc.len() < 32 {
            // Inline : bytes RLP injectés bruts (1 item RLP à la racine).
            s.append_raw(&enc, 1);
        } else {
            // Hashé : byte string de 32 bytes.
            let h = keccak256(&enc);
            s.append(&h.as_bytes().to_vec());
        }
    }

    /// Bytes de référence à insérer dans le parent :
    ///
    /// - Si l'encodage RLP fait **strictement moins de 32 bytes** :
    ///   l'encodage lui-même (inline).
    /// - Sinon : `Keccak256(encodage)` (32 bytes).
    ///
    /// Utilisé par la couche proof pour retrouver les enfants.
    #[must_use]
    pub fn reference_bytes(&self) -> Vec<u8> {
        let enc = self.encode_rlp();
        if enc.len() < 32 {
            enc
        } else {
            keccak256(&enc).as_bytes().to_vec()
        }
    }

    /// Hash du nœud (racine ou référence hashée) = `Keccak256(RLP)`.
    #[must_use]
    pub fn hash(&self) -> Hash32 {
        keccak256(&self.encode_rlp())
    }
}

/// Décode un nœud MPT depuis son encodage RLP.
pub fn decode_rlp(bytes: &[u8]) -> Result<Node, MptError> {
    let rlp = rlp::Rlp::new(bytes);
    if rlp.is_data() {
        let data = rlp.data().map_err(|_| MptError::MalformedNode)?;
        if data.is_empty() {
            return Ok(Node::Empty);
        }
        return Err(MptError::MalformedNode);
    }
    let count = rlp.item_count().map_err(|_| MptError::MalformedNode)?;
    match count {
        2 => {
            let hp_rlp = rlp.at(0).map_err(|_| MptError::MalformedNode)?;
            let hp: Vec<u8> = hp_rlp.data().map_err(|_| MptError::MalformedNode)?.to_vec();
            let (path, is_leaf) = from_hex_prefix(&hp)?;
            if is_leaf {
                let value_rlp = rlp.at(1).map_err(|_| MptError::MalformedNode)?;
                let value: Vec<u8> = value_rlp
                    .data()
                    .map_err(|_| MptError::MalformedNode)?
                    .to_vec();
                Ok(Node::Leaf { path, value })
            } else {
                let child = resolve_child_at(&rlp, 1)?;
                Ok(Node::Extension {
                    path,
                    child: Box::new(child),
                })
            }
        }
        17 => {
            let mut children: [Option<Box<Node>>; 16] = Default::default();
            for (i, slot) in children.iter_mut().enumerate() {
                let child = resolve_child_at(&rlp, i)?;
                if !matches!(child, Node::Empty) {
                    *slot = Some(Box::new(child));
                }
            }
            let value_rlp = rlp.at(16).map_err(|_| MptError::MalformedNode)?;
            let value_bytes: Vec<u8> = value_rlp
                .data()
                .map_err(|_| MptError::MalformedNode)?
                .to_vec();
            let value = if value_bytes.is_empty() {
                None
            } else {
                Some(value_bytes)
            };
            Ok(Node::Branch { children, value })
        }
        _ => Err(MptError::MalformedNode),
    }
}

/// Résout un enfant à l'index `index` du nœud RLP parent :
///
/// - si le slot est un **byte string** vide ou de 32 bytes → référence
///   hashée ou slot vide, non résolvable localement → `Node::Empty` ;
/// - si le slot est une **liste embeddée** → nœud inline, on le décode
///   récursivement.
fn resolve_child_at(parent: &rlp::Rlp, index: usize) -> Result<Node, MptError> {
    let child = parent.at(index).map_err(|_| MptError::MalformedNode)?;
    if child.is_data() {
        let d = child.data().map_err(|_| MptError::MalformedNode)?;
        if d.is_empty() || d.len() == 32 {
            return Ok(Node::Empty);
        }
        Err(MptError::MalformedNode)
    } else {
        decode_rlp(child.as_raw())
    }
}

/// Extrait les bytes de référence bruts d'un slot d'un nœud encodé.
///
/// - si le slot est un **byte string** : ses bytes décodés (32 bytes
///   pour un hash, `[]` pour un slot vide) ;
/// - si le slot est une **liste embeddée** (nœud inline) : les bytes RLP
///   complets du nœud (identiques à `Node::encode_rlp()`).
fn extract_child_ref(node_bytes: &[u8], index: usize) -> Result<Vec<u8>, MptError> {
    let rlp = rlp::Rlp::new(node_bytes);
    let child = rlp.at(index).map_err(|_| MptError::MalformedNode)?;
    if child.is_data() {
        Ok(child.data().map_err(|_| MptError::MalformedNode)?.to_vec())
    } else {
        Ok(child.as_raw().to_vec())
    }
}

/// Extrait les bytes de référence d'un slot d'une **branche** (index `0..16`).
pub fn extract_branch_child_ref(node_bytes: &[u8], index: usize) -> Result<Vec<u8>, MptError> {
    let rlp = rlp::Rlp::new(node_bytes);
    if !rlp.is_list() {
        return Err(MptError::MalformedNode);
    }
    if rlp.item_count().map_err(|_| MptError::MalformedNode)? != 17 {
        return Err(MptError::MalformedNode);
    }
    extract_child_ref(node_bytes, index)
}

/// Extrait les bytes de valeur d'une branche (slot 16).
pub fn extract_branch_value(node_bytes: &[u8]) -> Result<Option<Vec<u8>>, MptError> {
    let rlp = rlp::Rlp::new(node_bytes);
    if !rlp.is_list() {
        return Err(MptError::MalformedNode);
    }
    if rlp.item_count().map_err(|_| MptError::MalformedNode)? != 17 {
        return Err(MptError::MalformedNode);
    }
    let value_rlp = rlp.at(16).map_err(|_| MptError::MalformedNode)?;
    let v: Vec<u8> = value_rlp
        .data()
        .map_err(|_| MptError::MalformedNode)?
        .to_vec();
    Ok(if v.is_empty() { None } else { Some(v) })
}

/// Extrait la référence d'enfant d'une **extension**.
pub fn extract_extension_child_ref(node_bytes: &[u8]) -> Result<Vec<u8>, MptError> {
    let rlp = rlp::Rlp::new(node_bytes);
    if !rlp.is_list() {
        return Err(MptError::MalformedNode);
    }
    if rlp.item_count().map_err(|_| MptError::MalformedNode)? != 2 {
        return Err(MptError::MalformedNode);
    }
    extract_child_ref(node_bytes, 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_node_rlp_is_0x80() {
        assert_eq!(Node::Empty.encode_rlp(), vec![0x80]);
    }

    #[test]
    fn empty_node_hash_is_keccak_0x80() {
        assert_eq!(Node::Empty.hash(), keccak256(&[0x80]));
    }

    #[test]
    fn leaf_rlp_roundtrip() {
        let node = Node::Leaf {
            path: vec![0xa, 0xb, 0xc, 0xd],
            value: vec![0x01, 0x02],
        };
        let bytes = node.encode_rlp();
        let decoded = decode_rlp(&bytes).unwrap();
        assert_eq!(decoded, node);
    }

    #[test]
    fn extension_rlp_roundtrip_inline_child() {
        // Enfant < 32 bytes (leaf court) → référence inline.
        let child = Node::Leaf {
            path: vec![0x1, 0x2],
            value: vec![0xab],
        };
        let node = Node::Extension {
            path: vec![0xa, 0xb],
            child: Box::new(child.clone()),
        };
        let bytes = node.encode_rlp();
        let decoded = decode_rlp(&bytes).unwrap();
        match decoded {
            Node::Extension { path, child: c } => {
                assert_eq!(path, vec![0xa, 0xb]);
                assert_eq!(*c, child);
            }
            other => panic!("expected extension, got {other:?}"),
        }
    }

    #[test]
    fn branch_rlp_roundtrip() {
        let node = Node::Branch {
            children: {
                let mut c: [Option<Box<Node>>; 16] = Default::default();
                c[0x3] = Some(Box::new(Node::Leaf {
                    path: vec![0x1, 0x2],
                    value: vec![0xab],
                }));
                c[0xf] = Some(Box::new(Node::Leaf {
                    path: vec![],
                    value: vec![0xcd],
                }));
                c
            },
            value: Some(vec![0xee]),
        };
        let bytes = node.encode_rlp();
        let decoded = decode_rlp(&bytes).unwrap();
        assert_eq!(decoded, node);
    }

    #[test]
    fn reference_bytes_inline_when_small() {
        let node = Node::Leaf {
            path: vec![],
            value: vec![],
        };
        let enc = node.encode_rlp();
        assert!(enc.len() < 32);
        assert_eq!(node.reference_bytes(), enc);
    }

    #[test]
    fn reference_bytes_hashed_when_large() {
        let node = Node::Leaf {
            path: vec![],
            value: vec![0xff; 100],
        };
        let enc = node.encode_rlp();
        assert!(enc.len() >= 32);
        assert_eq!(node.reference_bytes(), node.hash().as_bytes().to_vec());
    }
}
