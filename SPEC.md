# dig-evidence — normative specification

`dig-evidence` is the DIG Network's library of ACTIVE on-chain evidence TYPES. This document is the
authoritative contract an independent reimplementation could be built against. Normative voice: MUST /
SHOULD / MUST NOT are binding.

## 1. Purpose and model

An **evidence type** is a value that proves a specific on-chain fact. Every evidence type in this crate
is **active**: it knows what it proves, GATHERS the specific on-chain information its proof needs through
an injected reader, and re-verifies offline. The crate holds NO key, signs nothing, and opens no network
connection of its own — the only I/O is the injected
[`dig_chainsource_interface::ChainSource`](https://docs.rs/dig-chainsource-interface).

The model is `dig-did::prove_lineage`/`AncestryProof` generalised:

- **Unforgeable by construction.** Every evidence type's fields are PRIVATE. The ONLY constructor is
  `Evidence::gather`, which authenticates each field against the injected reader (or, for a
  self-contained offline proof, against the supplied inputs). A value therefore witnesses that the proof
  genuinely held. A struct literal cannot fabricate one.
- **Pure over reads.** `gather` reads chain state only through the injected `ChainSource`. It performs
  no other I/O.
- **Fail-closed.** An unreadable chain, a missing or forged anchor, or a proof that does not fold is an
  `EvidenceError`. An unreliable read (`Err` from the source) MUST NOT be treated as a reliable absence.

## 2. The `Evidence` trait

```rust
pub trait Evidence: Sized {
    type Claim;
    fn gather<S: ChainSource>(claim: &Self::Claim, chain: &S) -> Result<Self, EvidenceError>;
    fn verify(&self) -> Result<(), EvidenceError>;
}
```

- `Claim` — the inputs identifying the specific claim to gather and verify.
- `gather` — authenticates the claim and returns the evidence, or fails closed.
- `verify` — re-verifies the evidence OFFLINE from its own gathered contents.

## 3. Evidence taxonomy (Phase 1)

| Type | Claim | Proves | Reads chain? |
|------|-------|--------|--------------|
| `RangeInclusionEvidence` | leaf + path + generation root | the range leaf folds to the claimed root | no (offline) |
| `RootAnchorEvidence` | store_id + generation root | the root is committed on-chain by the store's launcher-anchored lineage | yes |
| `ReadIntegrityEvidence` | store_id + generation root + range leaf + path | both of the above, bound to the same root | yes |

### 3.1 `RangeInclusionEvidence`

MUST verify that the supplied `leaf` folds, via the supplied bottom-up `path`, to `generation_root`,
using the `dig-capsule` merkle contract verbatim: leaf/node domain separation with
`LEAF_TAG = b"digstore:leaf:v1"` and `NODE_TAG = b"digstore:node:v1"`, an odd node carried up
unchanged, and the fold `node = SHA-256(NODE_TAG || left || right)`. A path that does not reach
`generation_root` MUST be rejected with `EvidenceError::ProofDoesNotFold`. `gather` is offline and MUST
ignore the injected chain.

### 3.2 `RootAnchorEvidence`

MUST anchor store identity on the launcher **coin** and never on a curried `launcher_id`. `gather`:

1. MUST read `coin_record(store_id)`. Absent → `LauncherNotFound`; unreadable → `Chain`. Because the
   coin is looked up BY `store_id`, its coin id IS `store_id` (`coin_id == store_id`), the unforgeable
   256-bit anchor.
2. MUST reject unless that coin's puzzle hash equals the singleton launcher puzzle hash
   (`chia_puzzles::SINGLETON_LAUNCHER_HASH`) → else `NotALauncher`. This is what defeats the forgeable
   curry: an attacker who curries `launcher_id = store_id` on their own launcher coin cannot make a
   genuine launcher coin exist AT `store_id`.
3. MUST resolve the authenticated singleton lineage via `resolve_singleton_lineage(store_id)` (a genuine
   forward walk from the launcher — the `ChainSource` contract). Absent → `NoLineage`.
4. MUST confirm `generation_root` is committed by a coin in that lineage: walking the lineage backward
   from the tip, each visited coin confirmed a genuine member (`SingletonLineage::contains`), hydrating
   each store coin (`dig_merkle::hydrate`) and comparing its committed `root_hash`. The curried
   `launcher_id == store_id` is checked per hop ONLY as defence-in-depth, never as the anchor. A root
   committed by no member → `RootNotCommitted`. The walk MUST be bounded (`MAX_LINEAGE_DEPTH`);
   exceeding it → `LineageTooDeep`.

### 3.3 `ReadIntegrityEvidence`

The composite `RangeInclusion(leaf ⇒ root) ∧ RootAnchor(root ⇐ launcher)`. `gather` MUST gather the
anchor leg first, then require the range proof to fold to the EXACT root the anchor proved (the two legs
are bound to the same 32 bytes). `verify` MUST re-verify both legs and re-assert the root binding
(`RootMismatch` otherwise). This is the single call a reader invokes before it caches and reshares
content.

## 4. Broadcastability classification

Evidence is classified by whether a third party can re-verify it from public inputs alone:

| Class | Meaning | Broadcastable? |
|-------|---------|----------------|
| **self-authenticating** | verifiable by anyone with the chain + the proof bytes (no private observation) | YES |
| **locally-observable** | its meaning depends on a private/local observation and MUST NOT be published as accusation | NO (#1438 anti-censorship) |

| Type | Class | Broadcastable? |
|------|-------|----------------|
| `RangeInclusionEvidence` | self-authenticating | yes — a merkle inclusion proof folds for anyone |
| `RootAnchorEvidence` | self-authenticating | yes — anyone with the chain re-derives the same anchor |
| `ReadIntegrityEvidence` | self-authenticating | yes — the conjunction of two self-authenticating proofs |

Phase 1 ships only self-authenticating types. Future locally-observable types (e.g. peer-honesty fraud
observations, #1438) MUST be marked non-broadcastable in this table: publishing a locally-observable
"proof" as an accusation is a censorship vector, because a third party cannot distinguish a true
observation from a fabricated one.

## 5. Backwards compatibility (§5.1)

Evidence over a `.dig` artifact MUST remain verifiable forever: a proof that folds/anchors under this
crate today MUST fold/anchor under every later version. Changes are ADDITIVE only — new evidence types,
new optional fields — never a change to the merkle domain-separation tags, the fold order, the
launcher-anchor rule, or an existing type's semantics. Golden fixtures (`tests/golden.rs`) pin the
byte-exact merkle root/leaf/path this crate accepts; a format change without an updated golden proof of
old-vector readability is incomplete.

## 6. Error taxonomy

`EvidenceError` variants are stable, catalogued failure reasons (§6.2): `Chain` (unreadable source, fail
closed), `LauncherNotFound`, `NotALauncher`, `NoLineage`, `RootNotCommitted`, `LineageTooDeep`,
`ProofDoesNotFold`, `RootMismatch`. Every gather/verify path returns one of these; none is ever
downgraded to a success.

## 7. Level + dependencies

`dig-evidence` is a LEVEL 20 (domain) crate. It depends ONLY on strictly-lower crates (reference-DOWN
only): L00 `dig-chainsource-interface` + `dig-urn-protocol`, L10 `dig-capsule` + `dig-merkle` +
`dig-did`, and the `chia-*` umbrella. It MUST NOT add a same-level (L20) or upward edge; a shared type
is exposed by re-export, never by an illegal edge. Consumers depend on JUST `dig-evidence` for the
evidence surface (the reused proof/coin shapes are re-exported).
