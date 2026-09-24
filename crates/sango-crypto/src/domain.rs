//! Domain separators normatifs de Sango V1.
//!
//! Chaque construction sensible (hash d’en-tête, hash de transaction,
//! signature de vote, etc.) DOIT être préfixée par un de ces domaines.
//!
//! Les bytes sont exactement les caractères ASCII affichés, sans terminateur
//! NUL, sans préfixe de longueur. Une implémentation NE DOIT PAS les
//! modifier.

// --- Domaines protocole ------------------------------------------------------

/// Hash du Genesis complet.
pub const GENESIS_V1: &[u8] = b"SANGO/GENESIS/V1";

/// Hash d’un `BlockHeader`.
pub const BLOCK_HEADER_V1: &[u8] = b"SANGO/BLOCK/HEADER/V1";

/// Hash d’une transaction native.
pub const TX_V1: &[u8] = b"SANGO/TX/V1";

/// Signature d’une `Proposal`.
pub const PROPOSAL_V1: &[u8] = b"SANGO/PROPOSAL/V1";

/// Signature d’un `Prevote`.
pub const PREVOTE_V1: &[u8] = b"SANGO/PREVOTE/V1";

/// Signature d’un `Precommit`.
pub const PRECOMMIT_V1: &[u8] = b"SANGO/PRECOMMIT/V1";

/// Hash d’une `Evidence`.
pub const EVIDENCE_V1: &[u8] = b"SANGO/EVIDENCE/V1";

/// Dérivation d’une adresse native.
pub const ADDRESS_V1: &[u8] = b"SANGO/ADDRESS/V1";

/// Dérivation de `prevrandao` EVM depuis le hash du bloc parent.
///
/// ```text
/// prevrandao = Keccak256("SANGO/EVM/PREVRANDAO/V1" || parent_block_hash)
/// ```
///
/// Déterministe et vérifiable par tout nœud. Aucune source de hasard locale.
pub const EVM_PREVRANDAO_V1: &[u8] = b"SANGO/EVM/PREVRANDAO/V1";

/// Combinaison des roots d’état (natif + EVM).
pub const STATE_ROOT_V1: &[u8] = b"SANGO/STATE/ROOT/V1";

/// Seed de sélection du proposer.
pub const PROPOSER_V1: &[u8] = b"SANGO/PROPOSER/V1";

// --- Domaines logs EVM -------------------------------------------------------

/// Feuille de log EVM.
pub const EVM_LOG_V1: &[u8] = b"SANGO/EVM/LOG/V1";

/// Nœud interne d’un arbre de logs EVM.
pub const EVM_LOG_NODE_V1: &[u8] = b"SANGO/EVM/LOG/NODE/V1";

/// Racine d’un arbre de logs EVM vide.
pub const EVM_LOG_EMPTY_V1: &[u8] = b"SANGO/EVM/LOG/EMPTY/V1";

// --- Native State Sparse Merkle Tree (FROZEN V1) ----------------------------

/// Préfixe de hashage des clés logiques d’état natif.
pub const NATIVE_STATE_KEY_V1: &[u8] = b"SANGO/STATE/KEY/V1";

/// Hash d’une feuille non vide du SMT natif.
pub const NATIVE_STATE_LEAF_V1: &[u8] = b"SANGO/STATE/LEAF/V1";

/// Hash d’un nœud interne du SMT natif.
pub const NATIVE_STATE_NODE_V1: &[u8] = b"SANGO/STATE/NODE/V1";

/// Hash d’une feuille vide du SMT natif.
pub const NATIVE_STATE_EMPTY_LEAF_V1: &[u8] = b"SANGO/STATE/EMPTY/LEAF/V1";

#[cfg(test)]
mod tests {
    use super::*;

    /// Tous les domain separators normatifs.
    const ALL_DOMAINS: &[&[u8]] = &[
        GENESIS_V1,
        BLOCK_HEADER_V1,
        TX_V1,
        PROPOSAL_V1,
        PREVOTE_V1,
        PRECOMMIT_V1,
        EVIDENCE_V1,
        ADDRESS_V1,
        STATE_ROOT_V1,
        PROPOSER_V1,
        EVM_LOG_V1,
        EVM_LOG_NODE_V1,
        EVM_LOG_EMPTY_V1,
        EVM_PREVRANDAO_V1,
        NATIVE_STATE_KEY_V1,
        NATIVE_STATE_LEAF_V1,
        NATIVE_STATE_NODE_V1,
        NATIVE_STATE_EMPTY_LEAF_V1,
    ];

    #[test]
    fn domains_are_ascii() {
        for d in ALL_DOMAINS {
            assert!(d.is_ascii(), "non-ASCII domain: {d:?}");
            assert!(!d.is_empty(), "empty domain");
        }
    }

    #[test]
    fn domains_are_unique() {
        for (i, a) in ALL_DOMAINS.iter().enumerate() {
            for (j, b) in ALL_DOMAINS.iter().enumerate().skip(i + 1) {
                assert_ne!(a, b, "duplicate domain at {i}/{j}");
            }
        }
    }
}
