//! Vérification statique d'une `Proposal`.
//!
//! Ces vérifications ne nécessitent **aucun accès à l'état ni à
//! l'exécution** : uniquement le contexte attendu (chain, epoch, height,
//! round, proposer) et le validator set (pour vérifier un éventuel PoLC).

use sango_crypto::derive_native_address;
use sango_primitives::{ChainId32, Epoch, Hash32, Height, PublicKey, Round};
use sango_types::Proposal;

use crate::error::ConsensusError;
use crate::validator_set::ValidatorSet;

/// Contexte attendu pour une proposition à vérifier.
#[derive(Clone, Copy, Debug)]
pub struct ProposalContext {
    /// Chain ID attendu.
    pub chain_id: ChainId32,
    /// Epoch attendu.
    pub epoch: Epoch,
    /// Hauteur attendue.
    pub height: Height,
    /// Round attendu.
    pub round: Round,
    /// Hash du bloc parent attendu (pour cohérence du header).
    pub parent_hash: Hash32,
}

/// Vérifie qu'une proposition est bien formée et cohérente avec le contexte.
///
/// ## Contrôles
///
/// 1. `version == PROTOCOL_VERSION_V1`.
/// 2. `chain_id`, `epoch`, `height`, `round` du proposal == contexte.
/// 3. `block.header` cohérent avec le contexte (chain, epoch, height,
///    round, parent_hash).
/// 4. `block_hash == block.hash()`.
/// 5. Le `proposer_address` dérive de la clé publique et correspond au
///    proposer attendu pour `(epoch, height, round, parent_hash)`.
/// 6. La signature du proposer est valide sur `DOMAIN_PROPOSAL_V1 ||
///    champs hors signature`.
/// 7. `valid_round` (si `Some`) strictement inférieur à `round`.
/// 8. `valid_round` et `valid_round_certificate` sont cohérents.
/// 9. Si `valid_round_certificate` est présent, il a un quorum `>2/3` sur
///    le `block_hash` du proposal au `valid_round` déclaré.
pub fn verify_proposal(
    proposal: &Proposal,
    ctx: &ProposalContext,
    validator_set: &ValidatorSet,
) -> Result<(), ConsensusError> {
    // (1) Version.
    if proposal.version != sango_types::PROTOCOL_VERSION_V1 {
        return Err(ConsensusError::UnsupportedProposalVersion(proposal.version));
    }

    // (2) Contexte.
    if proposal.chain_id != ctx.chain_id {
        return Err(ConsensusError::ChainIdMismatch {
            expected: ctx.chain_id,
            got: proposal.chain_id,
        });
    }
    if proposal.epoch != ctx.epoch {
        return Err(ConsensusError::EpochMismatch {
            expected: ctx.epoch,
            got: proposal.epoch,
        });
    }
    if proposal.height != ctx.height {
        return Err(ConsensusError::HeightMismatch {
            expected: ctx.height,
            got: proposal.height,
        });
    }
    if proposal.round != ctx.round {
        return Err(ConsensusError::RoundMismatch {
            expected: ctx.round,
            got: proposal.round,
        });
    }

    // (3) Header cohérent.
    let h = &proposal.block.header;
    if h.chain_id != ctx.chain_id {
        return Err(ConsensusError::ChainIdMismatch {
            expected: ctx.chain_id,
            got: h.chain_id,
        });
    }
    if h.epoch != ctx.epoch {
        return Err(ConsensusError::EpochMismatch {
            expected: ctx.epoch,
            got: h.epoch,
        });
    }
    if h.height != ctx.height {
        return Err(ConsensusError::HeightMismatch {
            expected: ctx.height,
            got: h.height,
        });
    }
    if h.round != ctx.round {
        return Err(ConsensusError::RoundMismatch {
            expected: ctx.round,
            got: h.round,
        });
    }
    if h.previous_block_hash != ctx.parent_hash {
        return Err(ConsensusError::ParentHashMismatch {
            expected: ctx.parent_hash,
            got: h.previous_block_hash,
        });
    }

    // (4) block_hash cohérent.
    let computed_hash = proposal.block.hash();
    if proposal.block_hash != computed_hash {
        return Err(ConsensusError::ProposalBlockHashMismatch {
            expected: computed_hash,
            got: proposal.block_hash,
        });
    }

    // (5) Proposer attendu.
    let expected_proposer = crate::select_proposer(
        &ctx.chain_id,
        ctx.epoch,
        ctx.height,
        ctx.round,
        &ctx.parent_hash,
        validator_set,
    )?;
    if proposal.proposer_address != expected_proposer {
        return Err(ConsensusError::WrongProposer {
            expected: expected_proposer,
            got: proposal.proposer_address,
        });
    }
    let proposer = validator_set
        .get(&expected_proposer)
        .ok_or(ConsensusError::UnknownValidator(expected_proposer))?;
    let proposer_pubkey: PublicKey = proposer.public_key;

    // Vérification supplémentaire de cohérence : l'adresse du proposeur
    // dérive bien de sa clé publique.
    let derived = derive_native_address(&proposer_pubkey);
    if derived != proposal.proposer_address {
        return Err(ConsensusError::WrongProposer {
            expected: derived,
            got: proposal.proposer_address,
        });
    }

    // (6) Signature du proposeur.
    proposal
        .verify(&proposer_pubkey)
        .map_err(|_| ConsensusError::InvalidSignature(expected_proposer))?;

    // (7) valid_round < round.
    if let Some(vr) = proposal.valid_round {
        if vr >= ctx.round {
            return Err(ConsensusError::InvalidValidRound {
                round: ctx.round,
                valid_round: vr,
            });
        }
    }

    // (8) Cohérence valid_round ↔ cert.
    match (
        proposal.valid_round,
        proposal.valid_round_certificate.as_ref(),
    ) {
        (None, Some(_)) => {
            return Err(ConsensusError::UnexpectedValidRoundCertificate);
        }
        (Some(_), None) => {
            return Err(ConsensusError::MissingValidRoundCertificate);
        }
        (None, None) => {}
        (Some(vr), Some(cert)) => {
            // (9) Vérification du certificat PoLC.
            if cert.chain_id != ctx.chain_id {
                return Err(ConsensusError::ChainIdMismatch {
                    expected: ctx.chain_id,
                    got: cert.chain_id,
                });
            }
            if cert.epoch != ctx.epoch {
                return Err(ConsensusError::EpochMismatch {
                    expected: ctx.epoch,
                    got: cert.epoch,
                });
            }
            if cert.height != ctx.height {
                return Err(ConsensusError::HeightMismatch {
                    expected: ctx.height,
                    got: cert.height,
                });
            }
            if cert.round != vr {
                return Err(ConsensusError::InvalidValidRound {
                    round: vr,
                    valid_round: cert.round,
                });
            }
            if cert.block_hash != Some(proposal.block_hash) {
                return Err(ConsensusError::PolcBlockHashMismatch);
            }

            // Recalcul local du quorum à partir du validator set.
            let mut power: u128 = 0;
            for entry in &cert.prevotes {
                let v = validator_set
                    .get(&entry.validator_address)
                    .ok_or(ConsensusError::UnknownValidator(entry.validator_address))?;
                // Vérifier la signature de la prevote individuelle.
                // Le payload signé est `DOMAIN_PREVOTE_V1 || chain_id ||
                // epoch || height || round || block_hash || validator_address`.
                let prevote = sango_types::Prevote {
                    chain_id: cert.chain_id,
                    epoch: cert.epoch,
                    height: cert.height,
                    round: cert.round,
                    block_hash: cert.block_hash,
                    validator_address: entry.validator_address,
                    validator_signature: entry.signature,
                };
                prevote
                    .verify(&v.public_key)
                    .map_err(|_| ConsensusError::InvalidSignature(entry.validator_address))?;
                power = power.saturating_add(v.voting_power);
            }
            if !validator_set.has_quorum(power) {
                return Err(ConsensusError::PolcWithoutQuorum {
                    power,
                    total: validator_set.total_power(),
                });
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator_set::Validator;
    use sango_crypto::{derive_native_address, NativeKeypair};
    use sango_primitives::{Height, Round, Signature};
    use sango_types::{Block, BlockHeader, Prevote, PrevoteCertificate, PrevoteEntry};

    fn chain() -> ChainId32 {
        ChainId32::from_bytes([0x11; 32])
    }

    fn hash(b: u8) -> Hash32 {
        Hash32::from_bytes([b; 32])
    }

    fn make_set(n: u8) -> (Vec<NativeKeypair>, ValidatorSet) {
        let mut kps = Vec::new();
        let mut vs = Vec::new();
        for i in 0..n {
            let kp = NativeKeypair::from_seed([i + 1; 32]);
            let pk = kp.public_key();
            let address = derive_native_address(&pk);
            vs.push(Validator {
                address,
                public_key: pk,
                voting_power: 100,
            });
            kps.push(kp);
        }
        (kps, ValidatorSet::new(vs).unwrap())
    }

    fn header_for(
        chain_id: ChainId32,
        epoch: Epoch,
        height: Height,
        round: Round,
        parent: Hash32,
    ) -> BlockHeader {
        BlockHeader {
            version: 1,
            chain_id,
            epoch,
            height,
            round,
            previous_block_hash: parent,
            timestamp: 1_700_000_000,
            proposer_address: NativeAddress::ZERO,
            transaction_root: Hash32::ZERO,
            state_root: Hash32::ZERO,
            receipt_root: Hash32::ZERO,
            gas_used: 0,
            gas_limit: 30_000_000,
            base_fee: 1,
        }
    }

    use sango_primitives::NativeAddress;

    /// Construit une proposition valide en utilisant `kps[0]` comme proposer.
    /// Renvoie aussi le contexte pour vérification.
    fn build_valid_proposal(
        kps: &[NativeKeypair],
        vs: &ValidatorSet,
    ) -> (Proposal, ProposalContext) {
        let parent = hash(0x99);
        let ctx = ProposalContext {
            chain_id: chain(),
            epoch: Epoch::new(0),
            height: Height::new(1),
            round: Round::new(0),
            parent_hash: parent,
        };

        // Calcul du proposer attendu.
        let proposer_addr = crate::select_proposer(
            &ctx.chain_id,
            ctx.epoch,
            ctx.height,
            ctx.round,
            &ctx.parent_hash,
            vs,
        )
        .unwrap();

        // Retrouver le keypair correspondant.
        let kp = kps
            .iter()
            .find(|kp| derive_native_address(&kp.public_key()) == proposer_addr)
            .unwrap();
        let proposer_pubkey = kp.public_key();

        let mut h = header_for(
            ctx.chain_id,
            ctx.epoch,
            ctx.height,
            ctx.round,
            ctx.parent_hash,
        );
        h.proposer_address = proposer_addr;

        let block = Block {
            header: h,
            transactions: Vec::new(),
        };
        let block_hash = block.hash();

        let proposal = Proposal {
            version: sango_types::PROTOCOL_VERSION_V1,
            chain_id: ctx.chain_id,
            epoch: ctx.epoch,
            height: ctx.height,
            round: ctx.round,
            block,
            block_hash,
            valid_round: None,
            valid_round_certificate: None,
            proposer_address: proposer_addr,
            proposer_signature: Signature::ZERO,
        }
        .sign(kp);

        let _ = proposer_pubkey;
        (proposal, ctx)
    }

    /// Re-signe la proposition avec le keypair du proposer attendu.
    ///
    /// Utile pour les tests qui mutent `valid_round` ou `valid_round_certificate`
    /// (les deux font partie des bytes signés).
    fn resign(p: &mut Proposal, kps: &[NativeKeypair], vs: &ValidatorSet, ctx: &ProposalContext) {
        let proposer_addr = crate::select_proposer(
            &ctx.chain_id,
            ctx.epoch,
            ctx.height,
            ctx.round,
            &ctx.parent_hash,
            vs,
        )
        .unwrap();
        let kp = kps
            .iter()
            .find(|kp| derive_native_address(&kp.public_key()) == proposer_addr)
            .unwrap();
        *p = p.sign(kp);
    }

    #[test]
    fn valid_proposal_passes() {
        let (kps, vs) = make_set(4);
        let (p, ctx) = build_valid_proposal(&kps, &vs);
        assert!(verify_proposal(&p, &ctx, &vs).is_ok());
    }

    #[test]
    fn rejects_wrong_version() {
        let (kps, vs) = make_set(4);
        let (mut p, ctx) = build_valid_proposal(&kps, &vs);
        p.version = 99;
        // Re-signer pour isoler le check de version.
        let _ = &kps;
        assert!(matches!(
            verify_proposal(&p, &ctx, &vs),
            Err(ConsensusError::UnsupportedProposalVersion(99))
        ));
    }

    #[test]
    fn rejects_wrong_chain_id() {
        let (kps, vs) = make_set(4);
        let (mut p, ctx) = build_valid_proposal(&kps, &vs);
        p.chain_id = ChainId32::from_bytes([0x99; 32]);
        assert!(matches!(
            verify_proposal(&p, &ctx, &vs),
            Err(ConsensusError::ChainIdMismatch { .. })
        ));
    }

    #[test]
    fn rejects_wrong_height() {
        let (kps, vs) = make_set(4);
        let (mut p, ctx) = build_valid_proposal(&kps, &vs);
        p.height = Height::new(42);
        assert!(matches!(
            verify_proposal(&p, &ctx, &vs),
            Err(ConsensusError::HeightMismatch { .. })
        ));
    }

    #[test]
    fn rejects_wrong_parent_hash() {
        let (kps, vs) = make_set(4);
        let (mut p, ctx) = build_valid_proposal(&kps, &vs);
        // Modifier le parent du header.
        p.block.header.previous_block_hash = hash(0xaa);
        // Le block_hash change → mismatch sur block_hash d'abord.
        assert!(verify_proposal(&p, &ctx, &vs).is_err());
    }

    #[test]
    fn rejects_block_hash_mismatch() {
        let (kps, vs) = make_set(4);
        let (mut p, _ctx) = build_valid_proposal(&kps, &vs);
        p.block_hash = hash(0xbb);
        let ctx = ProposalContext {
            chain_id: chain(),
            epoch: Epoch::new(0),
            height: Height::new(1),
            round: Round::new(0),
            parent_hash: hash(0x99),
        };
        assert!(matches!(
            verify_proposal(&p, &ctx, &vs),
            Err(ConsensusError::ProposalBlockHashMismatch { .. })
        ));
    }

    #[test]
    fn rejects_wrong_proposer() {
        let (kps, vs) = make_set(4);
        let (mut p, ctx) = build_valid_proposal(&kps, &vs);
        p.proposer_address = NativeAddress::from_bytes([0xab; 20]);
        assert!(matches!(
            verify_proposal(&p, &ctx, &vs),
            Err(ConsensusError::WrongProposer { .. })
        ));
    }

    #[test]
    fn rejects_bad_signature() {
        let (kps, vs) = make_set(4);
        let (mut p, ctx) = build_valid_proposal(&kps, &vs);
        p.proposer_signature = Signature::ZERO;
        assert!(matches!(
            verify_proposal(&p, &ctx, &vs),
            Err(ConsensusError::InvalidSignature(_))
        ));
    }

    #[test]
    fn rejects_valid_round_ge_round() {
        let (kps, vs) = make_set(4);
        let (mut p, ctx) = build_valid_proposal(&kps, &vs);
        // Construire un faux cert non-nil, avec un round >= proposal.round.
        let entry = PrevoteEntry {
            validator_address: p.proposer_address,
            signature: Signature::ZERO,
        };
        p.valid_round = Some(Round::new(1)); // proposal.round == 0
        p.valid_round_certificate = Some(PrevoteCertificate {
            version: 1,
            chain_id: p.chain_id,
            epoch: p.epoch,
            height: p.height,
            round: Round::new(1),
            block_hash: Some(p.block_hash),
            prevotes: vec![entry],
        });
        // Re-signer : valid_round fait partie des bytes signés.
        resign(&mut p, &kps, &vs, &ctx);
        assert!(matches!(
            verify_proposal(&p, &ctx, &vs),
            Err(ConsensusError::InvalidValidRound { .. })
        ));
    }

    #[test]
    fn rejects_missing_cert() {
        // On construit un proposal au round 1 avec `valid_round = Some(0)`
        // mais **sans** certificat. La règle (7) est satisfaite (0 < 1),
        // donc la règle (8) doit se déclencher : certificat manquant.
        let (kps, vs) = make_set(4);
        let parent = hash(0x99);
        let ctx = ProposalContext {
            chain_id: chain(),
            epoch: Epoch::new(0),
            height: Height::new(1),
            round: Round::new(1),
            parent_hash: parent,
        };
        let proposer_addr = crate::select_proposer(
            &ctx.chain_id,
            ctx.epoch,
            ctx.height,
            ctx.round,
            &ctx.parent_hash,
            &vs,
        )
        .unwrap();
        let kp = kps
            .iter()
            .find(|kp| derive_native_address(&kp.public_key()) == proposer_addr)
            .unwrap();

        let mut h = header_for(
            ctx.chain_id,
            ctx.epoch,
            ctx.height,
            ctx.round,
            ctx.parent_hash,
        );
        h.proposer_address = proposer_addr;
        let block = Block {
            header: h,
            transactions: Vec::new(),
        };
        let block_hash = block.hash();

        let proposal = Proposal {
            version: sango_types::PROTOCOL_VERSION_V1,
            chain_id: ctx.chain_id,
            epoch: ctx.epoch,
            height: ctx.height,
            round: ctx.round,
            block,
            block_hash,
            valid_round: Some(Round::new(0)),
            valid_round_certificate: None,
            proposer_address: proposer_addr,
            proposer_signature: Signature::ZERO,
        }
        .sign(kp);

        assert!(matches!(
            verify_proposal(&proposal, &ctx, &vs),
            Err(ConsensusError::MissingValidRoundCertificate)
        ));
    }

    #[test]
    fn rejects_unexpected_cert() {
        let (kps, vs) = make_set(4);
        let (mut p, ctx) = build_valid_proposal(&kps, &vs);
        p.valid_round = None;
        p.valid_round_certificate = Some(PrevoteCertificate {
            version: 1,
            chain_id: p.chain_id,
            epoch: p.epoch,
            height: p.height,
            round: Round::new(0),
            block_hash: Some(p.block_hash),
            prevotes: vec![],
        });
        assert!(matches!(
            verify_proposal(&p, &ctx, &vs),
            Err(ConsensusError::UnexpectedValidRoundCertificate)
        ));
    }

    #[test]
    fn valid_proposal_with_polc() {
        let (kps, vs) = make_set(4);
        let parent = hash(0x99);
        let ctx = ProposalContext {
            chain_id: chain(),
            epoch: Epoch::new(0),
            height: Height::new(1),
            round: Round::new(2),
            parent_hash: parent,
        };
        let proposer_addr = crate::select_proposer(
            &ctx.chain_id,
            ctx.epoch,
            ctx.height,
            ctx.round,
            &ctx.parent_hash,
            &vs,
        )
        .unwrap();
        let kp = kps
            .iter()
            .find(|kp| derive_native_address(&kp.public_key()) == proposer_addr)
            .unwrap();

        let mut h = header_for(
            ctx.chain_id,
            ctx.epoch,
            ctx.height,
            ctx.round,
            ctx.parent_hash,
        );
        h.proposer_address = proposer_addr;
        let block = Block {
            header: h,
            transactions: Vec::new(),
        };
        let block_hash = block.hash();

        // Construire un PoLC valide au round 0 pour ce bloc.
        let valid_round = Round::new(0);
        let mut prevotes = Vec::new();
        for kp_i in kps.iter() {
            let pk = kp_i.public_key();
            let addr = derive_native_address(&pk);
            let prevote = Prevote {
                chain_id: ctx.chain_id,
                epoch: ctx.epoch,
                height: ctx.height,
                round: valid_round,
                block_hash: Some(block_hash),
                validator_address: addr,
                validator_signature: Signature::ZERO,
            }
            .sign(kp_i);
            prevotes.push(PrevoteEntry {
                validator_address: addr,
                signature: prevote.validator_signature,
            });
        }
        prevotes.sort_by_key(|e| e.validator_address);

        let cert = PrevoteCertificate {
            version: 1,
            chain_id: ctx.chain_id,
            epoch: ctx.epoch,
            height: ctx.height,
            round: valid_round,
            block_hash: Some(block_hash),
            prevotes,
        };

        let proposal = Proposal {
            version: sango_types::PROTOCOL_VERSION_V1,
            chain_id: ctx.chain_id,
            epoch: ctx.epoch,
            height: ctx.height,
            round: ctx.round,
            block,
            block_hash,
            valid_round: Some(valid_round),
            valid_round_certificate: Some(cert),
            proposer_address: proposer_addr,
            proposer_signature: Signature::ZERO,
        }
        .sign(kp);

        assert!(verify_proposal(&proposal, &ctx, &vs).is_ok());
    }
}
