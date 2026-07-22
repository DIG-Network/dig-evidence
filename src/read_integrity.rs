//! [`ReadIntegrityEvidence`] — the composite proof a reader gathers before it caches + reshares content
//! (the MVP flywheel's read→verify→cache→reshare integrity gate).
//!
//! It is the conjunction of the two proofs a safe read needs:
//!
//! > `RangeInclusion(leaf ⇒ root)  ∧  RootAnchor(root ⇐ launcher)`
//!
//! - [`RangeInclusionEvidence`] proves the served range's leaf is included under a generation root.
//! - [`RootAnchorEvidence`] proves that SAME root is genuinely committed on-chain by the store's
//!   launcher-anchored lineage (#1473).
//!
//! Neither alone is sufficient: a range proof under an unanchored root proves nothing about the store,
//! and an anchored root without an inclusion proof says nothing about the bytes served. Binding them —
//! the range proof MUST fold to the exact root the anchor proves — is what lets a reader trust served
//! bytes enough to cache and re-serve them. `dig-download` / `dig-store-cache` invoke this single call.

use chia_protocol::Bytes32;
use dig_capsule::format::Bytes32 as CapsuleBytes32;
use dig_capsule::merkle::ProofStep;
use dig_chainsource_interface::ChainSource;

use crate::error::{EvidenceError, EvidenceResult};
use crate::evidence::Evidence;
use crate::range_inclusion::{RangeInclusionClaim, RangeInclusionEvidence};
use crate::root_anchor::{RootAnchorClaim, RootAnchorEvidence};

/// Re-expresses a chia [`Bytes32`] as a `dig-capsule` [`CapsuleBytes32`] — the SAME 32 bytes, viewed
/// through the merkle crate's newtype. This is the ONE place the two 32-byte views meet, so the
/// range-fold root and the chain-anchored root are provably the same bytes.
fn to_capsule_bytes(bytes: Bytes32) -> CapsuleBytes32 {
    let mut raw = [0u8; 32];
    raw.copy_from_slice(bytes.as_ref());
    CapsuleBytes32(raw)
}

/// What a read-integrity proof claims: that `range_leaf` (via `range_path`) is included under
/// `generation_root`, AND that `generation_root` is committed on-chain by the store `store_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadIntegrityClaim {
    /// The store's launcher coin id (`launcher coin_id == store_id`, the unforgeable anchor).
    pub store_id: Bytes32,
    /// The generation root both proofs bind to.
    pub generation_root: Bytes32,
    /// The served range's merkle leaf digest.
    pub range_leaf: CapsuleBytes32,
    /// The served range's bottom-up inclusion path.
    pub range_path: Vec<ProofStep>,
}

/// Authenticated composite evidence that a served range is both included under a generation root and
/// that the root is genuinely anchored on-chain — the single assurance a reader needs to cache +
/// reshare.
///
/// Its fields are PRIVATE: the only way to obtain a value is [`gather`](Evidence::gather), which
/// authenticates both legs and binds them to the same root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadIntegrityEvidence {
    range: RangeInclusionEvidence,
    anchor: RootAnchorEvidence,
}

impl ReadIntegrityEvidence {
    /// The range-inclusion leg (leaf ⇒ root).
    pub fn range(&self) -> &RangeInclusionEvidence {
        &self.range
    }

    /// The root-anchor leg (root ⇐ launcher).
    pub fn anchor(&self) -> &RootAnchorEvidence {
        &self.anchor
    }

    /// The store's launcher coin id this evidence is anchored to.
    pub fn store_id(&self) -> Bytes32 {
        self.anchor.store_id()
    }

    /// The generation root both legs bind to.
    pub fn generation_root(&self) -> Bytes32 {
        self.anchor.generation_root()
    }
}

impl Evidence for ReadIntegrityEvidence {
    type Claim = ReadIntegrityClaim;

    /// Gathers both legs against `chain` and binds them: the range proof is required to fold to the
    /// EXACT root the anchor proves, so the two describe the same content. Fails closed if either leg
    /// fails.
    fn gather<S: ChainSource>(claim: &Self::Claim, chain: &S) -> EvidenceResult<Self> {
        // Anchor first: prove the root is genuinely committed on-chain (the expensive, chain-reading
        // leg). Its authenticated root is then the ONLY root the range proof is allowed to fold to.
        let anchor = RootAnchorEvidence::gather(
            &RootAnchorClaim {
                store_id: claim.store_id,
                generation_root: claim.generation_root,
            },
            chain,
        )?;

        // Bind the range proof to the anchored root by passing that exact root as the claimed root: a
        // range that folds to any other root is rejected as not-folding.
        let range = RangeInclusionEvidence::gather(
            &RangeInclusionClaim {
                leaf: claim.range_leaf,
                path: claim.range_path.clone(),
                generation_root: to_capsule_bytes(anchor.generation_root()),
            },
            chain,
        )?;

        Ok(Self { range, anchor })
    }

    /// Re-verifies both legs offline and re-asserts they bind to the same root.
    fn verify(&self) -> EvidenceResult<()> {
        self.range.verify()?;
        self.anchor.verify()?;
        if self.range.generation_root() != to_capsule_bytes(self.anchor.generation_root()) {
            return Err(EvidenceError::RootMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_puzzle_types::standard::StandardArgs;
    use chia_wallet_sdk::test::Simulator;
    use dig_capsule::merkle::MerkleTree;
    use dig_chainsource_interface::MockChainSource;
    use dig_chainsource_interface::{CoinRecord, SingletonLineage};
    use dig_merkle::{mint_datastore, Owner};

    /// Builds a store whose committed root IS a real merkle-tree root, plus an inclusion proof for one
    /// leaf under it — so both legs can be satisfied by the same root.
    struct Fixture {
        source: MockChainSource,
        store_id: Bytes32,
        root: Bytes32,
        leaf: CapsuleBytes32,
        path: Vec<ProofStep>,
    }

    fn record(coin: chia_protocol::Coin, spent: Option<u32>) -> CoinRecord {
        CoinRecord {
            coin,
            confirmed_height: Some(1),
            spent_height: spent,
            timestamp: None,
            coinbase: false,
        }
    }

    fn fixture() -> anyhow::Result<Fixture> {
        // A real merkle tree; its root is what the store will commit on-chain.
        let chunks: Vec<Vec<u8>> = (0..6u8).map(|i| vec![i; 16]).collect();
        let tree = MerkleTree::build(&chunks);
        let root_capsule = tree.root();
        let proof = tree.prove(3).expect("index in range");
        let root = Bytes32::new(root_capsule.0);

        // Mint a store committing exactly that root.
        let mut sim = Simulator::new();
        let owner = sim.bls(1_000_000);
        let owner_ph: Bytes32 = StandardArgs::curry_tree_hash(owner.pk).into();
        let built = mint_datastore(
            owner.coin,
            Owner::Standard(owner.pk),
            root,
            None,
            None,
            None,
            None,
            None,
            owner_ph,
            vec![],
            0,
        )?;
        sim.spend_coins(built.coin_spends.clone(), std::slice::from_ref(&owner.sk))?;
        let minted = built.child.expect("child");
        let store_id = minted.info.launcher_id;
        let launcher_spend = built
            .coin_spends
            .iter()
            .find(|s| s.coin.coin_id() == store_id)
            .expect("launcher spend")
            .clone();
        let launcher = launcher_spend.coin;
        let eve = minted.coin;

        let source = MockChainSource::new()
            .with_coin(store_id, record(launcher, Some(2)))
            .with_coin(eve.coin_id(), record(eve, None))
            .with_spend(store_id, launcher_spend)
            .with_lineage(
                store_id,
                SingletonLineage::new(eve.coin_id(), [store_id, eve.coin_id()]),
            );

        Ok(Fixture {
            source,
            store_id,
            root,
            leaf: proof.leaf,
            path: proof.path,
        })
    }

    #[test]
    fn a_genuine_read_gathers_and_verifies() -> anyhow::Result<()> {
        let f = fixture()?;
        let claim = ReadIntegrityClaim {
            store_id: f.store_id,
            generation_root: f.root,
            range_leaf: f.leaf,
            range_path: f.path.clone(),
        };
        let evidence = ReadIntegrityEvidence::gather(&claim, &f.source).expect("genuine read");
        assert_eq!(evidence.store_id(), f.store_id);
        assert_eq!(evidence.generation_root(), f.root);
        assert!(evidence.verify().is_ok());
        Ok(())
    }

    #[test]
    fn a_range_under_an_unanchored_root_is_rejected() -> anyhow::Result<()> {
        let f = fixture()?;
        // The range leaf/path are for the real tree, but the claimed root is not the anchored one.
        let claim = ReadIntegrityClaim {
            store_id: f.store_id,
            generation_root: Bytes32::new([0xAB; 32]), // not committed on-chain
            range_leaf: f.leaf,
            range_path: f.path.clone(),
        };
        assert_eq!(
            ReadIntegrityEvidence::gather(&claim, &f.source).unwrap_err(),
            EvidenceError::RootNotCommitted
        );
        Ok(())
    }

    #[test]
    fn a_tampered_range_leaf_is_rejected_even_with_a_genuine_anchor() -> anyhow::Result<()> {
        let f = fixture()?;
        let claim = ReadIntegrityClaim {
            store_id: f.store_id,
            generation_root: f.root,                // genuinely anchored
            range_leaf: CapsuleBytes32([0xff; 32]), // but the served leaf is forged
            range_path: f.path.clone(),
        };
        assert_eq!(
            ReadIntegrityEvidence::gather(&claim, &f.source).unwrap_err(),
            EvidenceError::ProofDoesNotFold
        );
        Ok(())
    }
}
