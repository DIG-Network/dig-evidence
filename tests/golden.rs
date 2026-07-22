//! Golden range-inclusion fixtures — the §5.1 backwards-compatibility guard.
//!
//! A `.dig` is a permanent, on-chain-anchored artifact: a proof that folds today MUST fold forever.
//! These vectors pin the byte-exact merkle root, leaf, and inclusion path this crate accepts, so any
//! accidental change to the domain-separation tags (`digstore:leaf:v1` / `digstore:node:v1`), the fold
//! order, or the odd-node carry rule would break this test rather than silently rejecting historical
//! content. The vector is a 4-leaf tree over chunks `[i; 32]` for `i ∈ 0..4`, proving leaf index 2.

use dig_capsule::merkle::MerkleTree;
use dig_chainsource_interface::MockChainSource;
use dig_evidence::{
    CapsuleBytes32, Evidence, ProofStep, RangeInclusionClaim, RangeInclusionEvidence,
};

/// The pinned generation root of the golden 4-leaf tree. Regenerating the tree MUST reproduce this.
const GOLDEN_ROOT: &str = "a16ef0afe7416069cf9e0db568481c9f2b3842027d7656bc584e7ee6d18ab1d1";
/// The pinned leaf digest for index 2 (`SHA-256(LEAF_TAG || [2; 32])`).
const GOLDEN_LEAF: &str = "6fd744e3a5d8e2f679ace6f53099b145b1fb74bd1fb4158efb5845af0ac0b923";
/// The pinned inclusion path for index 2: (sibling hash, is_left).
const GOLDEN_PATH: [(&str, bool); 2] = [
    (
        "3bc8abb80e15a4b197cc040f465a1f26b7f55e4a71b215891740af5ff4d30b90",
        false,
    ),
    (
        "e1b4e32b8a7e42d5e13af2bd7f2f895f4d44758c3a955d0e4d8956e5ed38bb3a",
        true,
    ),
];

fn bytes(hex: &str) -> CapsuleBytes32 {
    CapsuleBytes32::from_hex(hex).expect("valid 32-byte hex")
}

fn golden_claim() -> RangeInclusionClaim {
    RangeInclusionClaim {
        leaf: bytes(GOLDEN_LEAF),
        path: GOLDEN_PATH
            .iter()
            .map(|(hash, is_left)| ProofStep {
                hash: bytes(hash),
                is_left: *is_left,
            })
            .collect(),
        generation_root: bytes(GOLDEN_ROOT),
    }
}

/// The pinned golden proof still folds to the pinned root — the permanent-readability guarantee.
#[test]
fn golden_range_proof_still_folds() {
    let evidence = RangeInclusionEvidence::gather(&golden_claim(), &MockChainSource::new())
        .expect("the golden proof must fold forever (§5.1)");
    assert_eq!(evidence.generation_root(), bytes(GOLDEN_ROOT));
    assert!(evidence.verify().is_ok());
}

/// Rebuilding the golden tree reproduces the pinned root, leaf, and path — proving the vector matches
/// the producer's current output (the two ends of the contract agree).
#[test]
fn golden_tree_regenerates_to_the_pinned_vector() {
    let chunks: Vec<Vec<u8>> = (0..4u8).map(|i| vec![i; 32]).collect();
    let tree = MerkleTree::build(&chunks);
    assert_eq!(
        tree.root().to_hex(),
        GOLDEN_ROOT,
        "root drifted from golden"
    );

    let proof = tree.prove(2).expect("index 2 in range");
    assert_eq!(proof.leaf.to_hex(), GOLDEN_LEAF, "leaf drifted from golden");
    let path: Vec<(String, bool)> = proof
        .path
        .iter()
        .map(|s| (s.hash.to_hex(), s.is_left))
        .collect();
    let expected: Vec<(String, bool)> = GOLDEN_PATH
        .iter()
        .map(|(h, l)| (h.to_string(), *l))
        .collect();
    assert_eq!(path, expected, "inclusion path drifted from golden");
}
