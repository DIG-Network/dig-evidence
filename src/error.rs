//! [`EvidenceError`] — the crate's fail-closed error taxonomy (SPEC §6).
//!
//! Every gather/verify path fails CLOSED: an unreadable chain, a missing coin, a forged anchor, or a
//! proof that does not fold is an `Err`, never a silently-accepted absence. The `None`-vs-`Err`
//! discipline of [`dig_chainsource_interface::ChainSource`] is preserved — a reliable "does not
//! exist" answer becomes a specific typed variant (e.g. [`EvidenceError::LauncherNotFound`]), while an
//! "could not answer" transport failure becomes [`EvidenceError::Chain`]. Both stop the proof; neither
//! is ever treated as "assume valid".

use thiserror::Error;

/// The single error type every [`Evidence`](crate::Evidence) gather/verify returns. Each variant is a
/// stable, catalogued failure reason (§6.2) so a consumer can branch on WHY a proof could not be
/// established without parsing prose.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EvidenceError {
    /// A [`ChainSource`](dig_chainsource_interface::ChainSource) read could not be answered (transport,
    /// timeout, malformed, unsupported). The answer is UNKNOWN — the proof fails closed, never
    /// degrading an unreliable read to "assume valid". Carries the source's `Display` string.
    #[error("chain read failed: {0}")]
    Chain(String),

    /// The claimed launcher coin (`store_id`) does not exist per the chain source. The unforgeable
    /// identity anchor is missing, so no root-anchor proof can be built (fail closed).
    #[error("launcher coin (store_id) not found on chain")]
    LauncherNotFound,

    /// A coin was found at `store_id`, but its puzzle hash is NOT the singleton launcher puzzle hash —
    /// so `store_id` is not a genuine launcher coin. Rejecting this is what makes the launcher-coin
    /// anchor unforgeable: identity is anchored on the launcher COIN, never a curried `launcher_id`.
    #[error("coin at store_id is not a singleton launcher")]
    NotALauncher,

    /// The store's singleton lineage could not be resolved — the launcher never produced a singleton,
    /// or it has been fully melted. Without an authenticated lineage the claimed root cannot be
    /// anchored (fail closed).
    #[error("no singleton lineage for store_id")]
    NoLineage,

    /// The claimed generation root is not committed by any coin in the store's authenticated lineage
    /// (within the bounded walk). The root is not genuinely anchored to this store → reject.
    #[error("generation root is not committed by any coin in the store lineage")]
    RootNotCommitted,

    /// The backward lineage walk exceeded [`MAX_LINEAGE_DEPTH`](crate::MAX_LINEAGE_DEPTH) without
    /// resolving the claim. Fails closed rather than walking unboundedly.
    #[error("store lineage walk exceeded the maximum depth")]
    LineageTooDeep,

    /// A merkle inclusion path did not fold to the claimed generation root. The supplied leaf is not
    /// provably contained under that root → reject.
    #[error("merkle inclusion proof does not fold to the claimed root")]
    ProofDoesNotFold,

    /// The two roots a composite proof must bind — the merkle-fold root and the chain-anchored root —
    /// are not the same 32 bytes. The range proof and the anchor proof describe different content, so
    /// their conjunction is meaningless → reject.
    #[error("range-inclusion root and chain-anchored root disagree")]
    RootMismatch,
}

/// A convenience result alias for evidence gather/verify.
pub type EvidenceResult<T> = Result<T, EvidenceError>;
