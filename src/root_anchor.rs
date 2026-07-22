//! [`RootAnchorEvidence`] (#1473) — ACTIVE proof that a claimed generation root is genuinely committed
//! on-chain by the store's own DataStore singleton.
//!
//! This is the crate's anti-rollback / anti-impostor anchor, and it enforces the ecosystem's
//! load-bearing security invariant (#1473, `canonical`):
//!
//! > A singleton's CURRIED `launcher_id` is FORGEABLE. Anchor identity on the launcher COIN, never the
//! > curry.
//!
//! Chia's singleton top-layer never binds the curried `SingletonStruct.launcher_id` to the coin that
//! actually launched the singleton — an attacker can launch from their OWN launcher coin
//! (`coin_id != store_id`) while currying `launcher_id = store_id`, set any state root, and hint the
//! tip to `store_id`. So a check of the curried `launcher_id == store_id` (or a hint discovery) is
//! spoofable. The ONLY unforgeable anchor is the launcher **coin_id == store_id** (a 256-bit hash
//! preimage an attacker cannot grind): trust chains to `coin_record(store_id)` — it exists, and its
//! puzzle hash IS the singleton launcher puzzle hash — and to the store's authenticated singleton
//! lineage (a genuine forward walk from that launcher, supplied by
//! [`ChainSource::resolve_singleton_lineage`]). The curried-`launcher_id == store_id` check is kept
//! ONLY as per-hop defence-in-depth, never as the anchor.
//!
//! [`gather`] therefore: (1) confirms `store_id` is a real launcher coin, (2) resolves the
//! authenticated lineage, then (3) walks that lineage backward from the tip — each hop confirmed a
//! genuine member — hydrating each store coin ([`dig_merkle::hydrate`]) until it finds the coin that
//! commits the claimed root. Anything missing fails closed.

use chia_protocol::Bytes32;
use chia_puzzles::SINGLETON_LAUNCHER_HASH;
use dig_chainsource_interface::ChainSource;
use dig_merkle::hydrate;

use crate::error::{EvidenceError, EvidenceResult};
use crate::evidence::{chain_err, Evidence};

/// The maximum number of lineage coins the backward walk will visit before failing closed with
/// [`EvidenceError::LineageTooDeep`]. Bounds the work an adversarial (deep) lineage can force.
pub const MAX_LINEAGE_DEPTH: usize = 100_000;

/// What a root-anchor proof claims: that `generation_root` is committed on-chain by the store whose
/// launcher coin id is `store_id`.
///
/// `store_id` MUST be the store's launcher COIN id (the unforgeable identity anchor). `generation_root`
/// is the `.dig` merkle root the caller claims the store committed at some generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootAnchorClaim {
    /// The store's launcher coin id (`launcher coin_id == store_id`, the unforgeable anchor).
    pub store_id: Bytes32,
    /// The generation root claimed to be committed by a coin in the store's lineage.
    pub generation_root: Bytes32,
}

/// Authenticated evidence that a generation root is committed by the store's on-chain lineage.
///
/// Its fields are PRIVATE and exposed only through accessors: the only way to obtain a value is
/// [`gather`](Evidence::gather), which authenticates the launcher-coin anchor, the lineage, and the
/// committing coin against the injected chain. A value witnesses that the root is genuinely anchored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootAnchorEvidence {
    store_id: Bytes32,
    generation_root: Bytes32,
    committing_coin: Bytes32,
    lineage_tip: Bytes32,
}

impl RootAnchorEvidence {
    /// The store's launcher coin id (the unforgeable identity anchor this evidence chained to).
    pub fn store_id(&self) -> Bytes32 {
        self.store_id
    }

    /// The generation root proven to be committed on-chain by the store.
    pub fn generation_root(&self) -> Bytes32 {
        self.generation_root
    }

    /// The lineage coin whose DataStore state committed `generation_root`.
    pub fn committing_coin(&self) -> Bytes32 {
        self.committing_coin
    }

    /// The store singleton's current unspent tip at gather time.
    pub fn lineage_tip(&self) -> Bytes32 {
        self.lineage_tip
    }
}

impl Evidence for RootAnchorEvidence {
    type Claim = RootAnchorClaim;

    /// Gathers + authenticates the on-chain anchor for `claim` (see the module docs for the
    /// launcher-coin invariant). Fails closed on a missing/forged launcher, an absent lineage, an
    /// unreadable chain, or a root committed by no coin in the lineage.
    fn gather<S: ChainSource>(claim: &Self::Claim, chain: &S) -> EvidenceResult<Self> {
        // (1) The unforgeable identity anchor: a coin genuinely exists AT `store_id`, and it is a
        // singleton LAUNCHER coin. Because it was looked up BY `store_id`, its coin id IS `store_id`
        // (coin_id == store_id) — the 256-bit preimage an attacker cannot grind. A curried
        // `launcher_id == store_id` is NOT trusted here; only the launcher coin is.
        let launcher = chain
            .coin_record(claim.store_id)
            .map_err(chain_err)?
            .ok_or(EvidenceError::LauncherNotFound)?;
        if launcher.coin.puzzle_hash != Bytes32::from(SINGLETON_LAUNCHER_HASH) {
            return Err(EvidenceError::NotALauncher);
        }

        // (2) The authenticated lineage — a genuine forward walk from the launcher to its tip (the
        // ChainSource contract). Membership in THIS set is the authority test.
        let lineage = chain
            .resolve_singleton_lineage(claim.store_id)
            .map_err(chain_err)?
            .ok_or(EvidenceError::NoLineage)?;

        // (3) Walk the lineage backward from the tip, hydrating each store coin, until one commits the
        // claimed root. Each visited coin is confirmed a genuine lineage member; the curried
        // `launcher_id == store_id` is a per-hop defence-in-depth check, never the anchor.
        let mut current = lineage.tip();
        for _ in 0..MAX_LINEAGE_DEPTH {
            if !lineage.contains(current) {
                return Err(EvidenceError::RootNotCommitted);
            }

            let record = chain
                .coin_record(current)
                .map_err(chain_err)?
                .ok_or(EvidenceError::RootNotCommitted)?;

            // The spend that CREATED `current` is the spend of its parent; hydrating it reconstructs
            // `current`'s DataStore state (and the root it committed).
            if let Some(creating_spend) = chain
                .coin_spend(record.coin.parent_coin_info)
                .map_err(chain_err)?
            {
                if let Ok(store) = hydrate(&creating_spend) {
                    if store.info.launcher_id == claim.store_id
                        && store.info.metadata.root_hash == claim.generation_root
                    {
                        return Ok(Self {
                            store_id: claim.store_id,
                            generation_root: claim.generation_root,
                            committing_coin: current,
                            lineage_tip: lineage.tip(),
                        });
                    }
                }
            }

            // Step to the parent; stop once we reach the launcher (which commits no store root).
            let parent = record.coin.parent_coin_info;
            if parent == claim.store_id {
                return Err(EvidenceError::RootNotCommitted);
            }
            current = parent;
        }

        Err(EvidenceError::LineageTooDeep)
    }

    /// Re-asserts the anchor's internal invariant OFFLINE: the evidence names a committing coin and its
    /// identity is anchored on the launcher coin (`store_id`). The chain-authenticated facts were
    /// established at [`gather`](Evidence::gather) time (the value cannot be forged), so an offline
    /// re-check without the chain confirms only self-coherence.
    fn verify(&self) -> EvidenceResult<()> {
        if self.committing_coin == Bytes32::default() || self.store_id == Bytes32::default() {
            return Err(EvidenceError::RootNotCommitted);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_protocol::Coin;
    use chia_puzzle_types::standard::StandardArgs;
    use chia_wallet_sdk::test::Simulator;
    use dig_chainsource_interface::MockChainSource;
    use dig_chainsource_interface::{CoinRecord, SingletonLineage};
    use dig_merkle::{mint_datastore, Owner};

    /// A real minted store: returns the launcher coin, the eve store coin, the launcher spend, and the
    /// committed root — enough to load an authentic [`MockChainSource`] fixture.
    struct MintedStore {
        launcher: Coin,
        eve: Coin,
        launcher_spend: chia_protocol::CoinSpend,
        store_id: Bytes32,
        root: Bytes32,
    }

    fn mint(root: Bytes32) -> anyhow::Result<MintedStore> {
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
        let minted = built.child.expect("mint yields a child");
        let store_id = minted.info.launcher_id;
        let launcher_spend = built
            .coin_spends
            .iter()
            .find(|s| s.coin.coin_id() == store_id)
            .expect("launcher spend present")
            .clone();
        Ok(MintedStore {
            launcher: launcher_spend.coin,
            eve: minted.coin,
            launcher_spend,
            store_id,
            root,
        })
    }

    fn record(coin: Coin, spent_height: Option<u32>) -> CoinRecord {
        CoinRecord {
            coin,
            confirmed_height: Some(1),
            spent_height,
            timestamp: None,
            coinbase: false,
        }
    }

    /// An authentic chain fixture for a minted store: the launcher coin (spent), the eve coin
    /// (unspent tip), the launcher spend, and the lineage launcher -> eve.
    fn authentic_source(m: &MintedStore) -> MockChainSource {
        MockChainSource::new()
            .with_coin(m.store_id, record(m.launcher, Some(2)))
            .with_coin(m.eve.coin_id(), record(m.eve, None))
            .with_spend(m.store_id, m.launcher_spend.clone())
            .with_lineage(
                m.store_id,
                SingletonLineage::new(m.eve.coin_id(), [m.store_id, m.eve.coin_id()]),
            )
    }

    #[test]
    fn a_genuine_root_anchor_gathers_and_verifies() -> anyhow::Result<()> {
        let m = mint(Bytes32::new([0x5a; 32]))?;
        let source = authentic_source(&m);
        let claim = RootAnchorClaim {
            store_id: m.store_id,
            generation_root: m.root,
        };
        let evidence = RootAnchorEvidence::gather(&claim, &source).expect("genuine anchor");
        assert_eq!(evidence.store_id(), m.store_id);
        assert_eq!(evidence.generation_root(), m.root);
        assert_eq!(evidence.committing_coin(), m.eve.coin_id());
        assert!(evidence.verify().is_ok());
        Ok(())
    }

    #[test]
    fn a_root_never_committed_is_rejected() -> anyhow::Result<()> {
        let m = mint(Bytes32::new([0x5a; 32]))?;
        let source = authentic_source(&m);
        let claim = RootAnchorClaim {
            store_id: m.store_id,
            generation_root: Bytes32::new([0xAA; 32]), // never committed by this store
        };
        assert_eq!(
            RootAnchorEvidence::gather(&claim, &source).unwrap_err(),
            EvidenceError::RootNotCommitted
        );
        Ok(())
    }

    /// The launcher-anchor defence (#1473): a coin exists at `store_id` but its puzzle hash is NOT the
    /// singleton launcher puzzle hash — so it is not a genuine launcher coin. An attacker who curries
    /// `launcher_id = store_id` on their own coin cannot satisfy this, so the impostor is rejected
    /// BEFORE any lineage/root is trusted.
    #[test]
    fn an_impostor_whose_store_id_coin_is_not_a_launcher_is_rejected() {
        let store_id = Bytes32::new([0x11; 32]);
        let impostor = Coin::new(Bytes32::new([0x99; 32]), Bytes32::new([0x22; 32]), 1);
        let source = MockChainSource::new()
            .with_coin(store_id, record(impostor, Some(2)))
            // Even a fabricated lineage claiming the root must not be trusted — the launcher gate
            // rejects first.
            .with_lineage(store_id, SingletonLineage::single(store_id));
        let claim = RootAnchorClaim {
            store_id,
            generation_root: Bytes32::new([0x33; 32]),
        };
        assert_eq!(
            RootAnchorEvidence::gather(&claim, &source).unwrap_err(),
            EvidenceError::NotALauncher
        );
    }

    #[test]
    fn an_absent_launcher_is_rejected() {
        let claim = RootAnchorClaim {
            store_id: Bytes32::new([0x44; 32]),
            generation_root: Bytes32::new([0x55; 32]),
        };
        assert_eq!(
            RootAnchorEvidence::gather(&claim, &MockChainSource::new()).unwrap_err(),
            EvidenceError::LauncherNotFound
        );
    }

    #[test]
    fn an_unreadable_chain_fails_closed() {
        use dig_chainsource_interface::ChainSourceError;
        let source = MockChainSource::new().fail_with(ChainSourceError::Timeout);
        let claim = RootAnchorClaim {
            store_id: Bytes32::new([0x44; 32]),
            generation_root: Bytes32::new([0x55; 32]),
        };
        assert!(matches!(
            RootAnchorEvidence::gather(&claim, &source).unwrap_err(),
            EvidenceError::Chain(_)
        ));
    }

    #[test]
    fn a_launcher_with_no_lineage_is_rejected() -> anyhow::Result<()> {
        let m = mint(Bytes32::new([0x5a; 32]))?;
        // Launcher coin present + valid, but no lineage resolves (fully melted / unlaunched view).
        let source = MockChainSource::new().with_coin(m.store_id, record(m.launcher, Some(2)));
        let claim = RootAnchorClaim {
            store_id: m.store_id,
            generation_root: m.root,
        };
        assert_eq!(
            RootAnchorEvidence::gather(&claim, &source).unwrap_err(),
            EvidenceError::NoLineage
        );
        Ok(())
    }
}
