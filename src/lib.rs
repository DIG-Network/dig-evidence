//! # dig-evidence — the DIG Network's library of ACTIVE on-chain evidence types
//!
//! One home for the evidence/proof TYPES the ecosystem produces and verifies. Every type here is an
//! ACTIVE piece of evidence: it (a) knows what it proves, (b) GATHERS the specific on-chain
//! information its proof needs through an INJECTED [`ChainSource`] reader (never taking an upward
//! dependency on a node or transport), and (c) re-verifies offline from its own gathered contents.
//!
//! ## The pattern (modeled on `dig-did::prove_lineage`)
//!
//! Each type implements the [`Evidence`] trait and follows the same unforgeable-by-construction
//! discipline as `dig-did`'s `AncestryProof`:
//!
//! - **Private fields.** A value cannot be forged by a struct literal — the only way to obtain one is
//!   [`Evidence::gather`], which authenticates every field against the injected reader (or, for a
//!   self-contained offline proof, against the supplied inputs). Holding a value witnesses the proof.
//! - **Gather-only construction.** Construction reads chain state through the injected `ChainSource`
//!   and authenticates it; it holds NO key, signs nothing, and does its own no network I/O.
//! - **Fail-closed.** An unreadable chain, a missing/forged anchor, or a proof that does not fold is
//!   an [`EvidenceError`], never a silently-accepted absence.
//!
//! ## Phase 1 evidence types (the MVP flywheel read→verify→cache→reshare integrity gate)
//!
//! | Type | Proves | Class |
//! |------|--------|-------|
//! | [`RangeInclusionEvidence`] | a content range's leaf is included under a generation root | self-authenticating (offline) |
//! | [`RootAnchorEvidence`] | a generation root is committed on-chain by the store's launcher-anchored lineage | locally-observable (chain read) |
//! | [`ReadIntegrityEvidence`] | both of the above, bound to the same root — the read→cache→reshare gate | composite |
//!
//! See `SPEC.md` for the full evidence taxonomy and the self-authenticating (broadcastable) vs
//! locally-observable (NEVER broadcastable, #1438 anti-censorship) classification table.
//!
//! ## Reused primitives
//!
//! The merkle inclusion machinery is REUSED verbatim from `dig-capsule` ([`MerkleProof`] /
//! [`ProofStep`], with the `digstore:leaf:v1` / `digstore:node:v1` domain-separation tags), the
//! DataStore on-chain parse from `dig-merkle`, and the injected reader from
//! `dig-chainsource-interface` — this crate reinvents no crypto and cannot skew from the canonical
//! read-crypto.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod evidence;
mod range_inclusion;
mod read_integrity;
mod root_anchor;

pub use error::{EvidenceError, EvidenceResult};
pub use evidence::Evidence;
pub use range_inclusion::{RangeInclusionClaim, RangeInclusionEvidence};
pub use read_integrity::{ReadIntegrityClaim, ReadIntegrityEvidence};
pub use root_anchor::{RootAnchorClaim, RootAnchorEvidence, MAX_LINEAGE_DEPTH};

// --- Re-exports: the shared building blocks a consumer needs to construct claims + read evidence,
// so a downstream crate depends on JUST dig-evidence for the evidence surface. ---

/// The injected reads-only chain seam every active evidence type gathers through, plus the coin/lineage
/// shapes it reads. Re-exported so consumers construct claims without a direct
/// `dig-chainsource-interface` dependency.
pub use dig_chainsource_interface::{ChainSource, CoinRecord, SingletonLineage};

/// The merkle inclusion-proof shapes and domain-separation tags, REUSED verbatim from `dig-capsule`.
/// A [`RangeInclusionClaim`] is built from a [`ProofStep`] path; the tags are the byte-for-byte
/// producer contract.
pub use dig_capsule::format::Bytes32 as CapsuleBytes32;
pub use dig_capsule::merkle::{MerkleProof, ProofStep, LEAF_TAG, NODE_TAG};

/// The DID ancestry-proof this crate's pattern generalises, re-exported so the singleton-lineage
/// evidence story lives behind one import. (`dig-did`'s `prove_lineage` remains the reference impl.)
pub use dig_did::{AncestryProof, LineageModel};

/// The canonical URN content-verification contract (`FoldedProof` + the gate-then-decrypt
/// `verify_inclusion` / `verify_and_decrypt` over injected crypto), re-exported so a consumer reaches
/// the blind-client read-verification surface through `dig-evidence` alongside the on-chain evidence
/// types. This is the URN-level counterpart to [`RangeInclusionEvidence`].
pub use dig_urn_protocol::{verify_and_decrypt, verify_inclusion, ContentCrypto, FoldedProof};
