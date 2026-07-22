//! The [`Evidence`] trait — the ONE shape every active on-chain evidence type in this crate wears.
//!
//! An evidence type answers three questions about ITSELF: what it proves (its [`Claim`](Evidence::Claim)),
//! how to GATHER the specific on-chain information that proof needs (through an injected
//! [`ChainSource`]), and how to re-VERIFY it. This is the `dig-did::prove_lineage`/`AncestryProof`
//! pattern generalised: construction is gather-only and authenticated against the injected reader, the
//! fields are private (a value cannot be forged by a struct literal), and every path is pure over the
//! reads and fails closed.

use dig_chainsource_interface::ChainSource;

use crate::error::EvidenceResult;

/// An active piece of on-chain evidence: a type that knows what it proves, gathers the on-chain
/// information its proof needs, and re-verifies offline from its own gathered contents.
///
/// ## Why gather-only construction matters
///
/// The ONLY way to obtain a value of an `Evidence` type is [`gather`](Evidence::gather), which
/// authenticates every field against the injected [`ChainSource`] (or, for a self-contained offline
/// proof, against the supplied inputs). Implementors keep their fields PRIVATE, so a caller can never
/// fabricate "proven" evidence with a struct literal — holding a value is itself the assurance the
/// proof genuinely held at gather time. [`verify`](Evidence::verify) re-checks the evidence offline
/// from its own contents (a cheap, network-free re-assertion of the invariant).
pub trait Evidence: Sized {
    /// What this evidence proves — the inputs identifying the specific claim to gather + verify.
    type Claim;

    /// Gathers the on-chain information this proof needs for `claim`, reading chain state through the
    /// injected `chain`, and returns the authenticated evidence — or fails closed.
    ///
    /// Pure over the injected reads: NO keys, NO signing, NO network of its own (the reader is the only
    /// I/O). A self-contained offline evidence type (one whose proof is fully supplied in the claim)
    /// may ignore `chain` and authenticate the supplied inputs directly.
    ///
    /// # Errors
    ///
    /// Returns an [`EvidenceError`](crate::EvidenceError) on any gap or mismatch — an unreadable chain,
    /// a missing/forged anchor, or a proof that does not fold. Never degrades an unreliable read to
    /// "assume valid".
    fn gather<S: ChainSource>(claim: &Self::Claim, chain: &S) -> EvidenceResult<Self>;

    /// Re-verifies the evidence OFFLINE from its own gathered contents, returning `Ok(())` when the
    /// proven invariant still holds.
    ///
    /// # Errors
    ///
    /// Returns an [`EvidenceError`](crate::EvidenceError) if the evidence's own contents are internally
    /// inconsistent (e.g. a stored merkle path no longer folds to the stored root).
    fn verify(&self) -> EvidenceResult<()>;
}

/// Maps a [`ChainSource`] error into [`EvidenceError::Chain`](crate::EvidenceError::Chain), preserving
/// its `Display` string. The single funnel every gather path uses so an unreliable read always fails
/// closed as `Chain`, never as a false absence.
pub(crate) fn chain_err<E: core::fmt::Display>(error: E) -> crate::EvidenceError {
    crate::EvidenceError::Chain(error.to_string())
}
