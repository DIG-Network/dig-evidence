//! [`RangeInclusionEvidence`] (#1437) — proof that a content range's leaf is included under a claimed
//! generation root.
//!
//! This is a SELF-CONTAINED, OFFLINE evidence type: everything it needs is supplied in the claim (a
//! leaf digest + its bottom-up inclusion path + the claimed generation root), so [`gather`] performs
//! no chain reads — it authenticates the supplied inputs by folding the path and confirming it reaches
//! the claimed root. The merkle machinery is REUSED from `dig-capsule` verbatim
//! ([`dig_capsule::merkle::MerkleProof`] / [`ProofStep`]), so the domain-separation tags
//! ([`LEAF_TAG`](dig_capsule::merkle::LEAF_TAG) = `b"digstore:leaf:v1"` /
//! [`NODE_TAG`](dig_capsule::merkle::NODE_TAG) = `b"digstore:node:v1"`) are byte-for-byte identical to
//! the producer's — a range proof this crate accepts is exactly a range proof the store emitted.
//!
//! Proving inclusion under a root does NOT prove the root is genuine; pairing it with
//! [`RootAnchorEvidence`](crate::RootAnchorEvidence) does (see [`ReadIntegrityEvidence`](crate::ReadIntegrityEvidence)).

use dig_capsule::format::Bytes32 as CapsuleBytes32;
use dig_capsule::merkle::{MerkleProof, ProofStep};
use dig_chainsource_interface::ChainSource;

use crate::error::{EvidenceError, EvidenceResult};
use crate::evidence::Evidence;

/// What a range-inclusion proof claims: that `leaf` folds, via `path`, to `generation_root`.
///
/// `leaf` is the range's merkle leaf digest and `path` is its bottom-up sibling path — both exactly as
/// produced by `dig-capsule`'s [`MerkleTree`](dig_capsule::merkle::MerkleTree). `generation_root` is
/// the root the caller claims the leaf is contained under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeInclusionClaim {
    /// The range's merkle leaf digest (the value the inclusion path starts from).
    pub leaf: CapsuleBytes32,
    /// The bottom-up inclusion path (sibling + side per level), verbatim from the producer.
    pub path: Vec<ProofStep>,
    /// The generation root the leaf is claimed to be included under.
    pub generation_root: CapsuleBytes32,
}

/// Authenticated evidence that a range leaf is included under a generation root.
///
/// Its fields are PRIVATE and exposed only through accessors: the only way to obtain a value is
/// [`gather`](Evidence::gather), which folds the supplied path and confirms it reaches the claimed
/// root. A value therefore witnesses that the inclusion genuinely holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeInclusionEvidence {
    proof: MerkleProof,
}

impl RangeInclusionEvidence {
    /// The generation root the range leaf is proven to be included under.
    pub fn generation_root(&self) -> CapsuleBytes32 {
        self.proof.root
    }

    /// The range's merkle leaf digest this evidence proves inclusion of.
    pub fn leaf(&self) -> CapsuleBytes32 {
        self.proof.leaf
    }

    /// The inclusion path (sibling hashes + sides) folded to reach the root.
    pub fn path(&self) -> &[ProofStep] {
        &self.proof.path
    }
}

impl Evidence for RangeInclusionEvidence {
    type Claim = RangeInclusionClaim;

    /// Authenticates the supplied inclusion inputs OFFLINE — `chain` is unused because a range proof is
    /// fully self-contained. Builds the [`MerkleProof`] from the claim and folds it; a path that does
    /// not reach `generation_root` is rejected with [`EvidenceError::ProofDoesNotFold`].
    fn gather<S: ChainSource>(claim: &Self::Claim, _chain: &S) -> EvidenceResult<Self> {
        let proof = MerkleProof {
            leaf: claim.leaf,
            path: claim.path.clone(),
            root: claim.generation_root,
        };
        if !proof.verify() {
            return Err(EvidenceError::ProofDoesNotFold);
        }
        Ok(Self { proof })
    }

    /// Re-folds the stored path offline and confirms it still reaches the stored root.
    fn verify(&self) -> EvidenceResult<()> {
        if self.proof.verify() {
            Ok(())
        } else {
            Err(EvidenceError::ProofDoesNotFold)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_capsule::merkle::MerkleTree;
    use dig_chainsource_interface::MockChainSource;

    /// Builds a tree over `n` distinct chunks and returns (root, leaf, path) for `index`.
    fn tree_proof(n: usize, index: usize) -> (CapsuleBytes32, CapsuleBytes32, Vec<ProofStep>) {
        let chunks: Vec<Vec<u8>> = (0..n).map(|i| vec![i as u8; 8]).collect();
        let tree = MerkleTree::build(&chunks);
        let proof = tree.prove(index).expect("index in range");
        (tree.root(), proof.leaf, proof.path)
    }

    #[test]
    fn a_valid_range_proof_gathers_and_verifies() {
        let (root, leaf, path) = tree_proof(5, 2);
        let claim = RangeInclusionClaim {
            leaf,
            path,
            generation_root: root,
        };
        let evidence =
            RangeInclusionEvidence::gather(&claim, &MockChainSource::new()).expect("valid proof");
        assert_eq!(evidence.generation_root(), root);
        assert_eq!(evidence.leaf(), leaf);
        assert!(evidence.verify().is_ok());
    }

    #[test]
    fn a_tampered_leaf_is_rejected() {
        let (root, _leaf, path) = tree_proof(5, 2);
        let forged = RangeInclusionClaim {
            leaf: CapsuleBytes32([0xff; 32]),
            path,
            generation_root: root,
        };
        assert_eq!(
            RangeInclusionEvidence::gather(&forged, &MockChainSource::new()).unwrap_err(),
            EvidenceError::ProofDoesNotFold
        );
    }

    #[test]
    fn a_wrong_claimed_root_is_rejected() {
        let (_root, leaf, path) = tree_proof(8, 5);
        let forged = RangeInclusionClaim {
            leaf,
            path,
            generation_root: CapsuleBytes32([0x00; 32]),
        };
        assert_eq!(
            RangeInclusionEvidence::gather(&forged, &MockChainSource::new()).unwrap_err(),
            EvidenceError::ProofDoesNotFold
        );
    }

    #[test]
    fn a_tampered_path_step_is_rejected() {
        let (root, leaf, mut path) = tree_proof(6, 1);
        if let Some(step) = path.first_mut() {
            step.hash = CapsuleBytes32([0x77; 32]);
        }
        let forged = RangeInclusionClaim {
            leaf,
            path,
            generation_root: root,
        };
        assert_eq!(
            RangeInclusionEvidence::gather(&forged, &MockChainSource::new()).unwrap_err(),
            EvidenceError::ProofDoesNotFold
        );
    }
}
