# dig-evidence

The DIG Network's library of **active on-chain evidence types**. One home for the evidence/proof types
the ecosystem produces and verifies.

Every type here is **active**: it (a) knows what it proves, (b) GATHERS the specific on-chain
information its proof needs through an injected `ChainSource` reader, and (c) re-verifies offline from
its own gathered contents. Modeled on `dig-did`'s `prove_lineage`/`AncestryProof`: private fields
(unforgeable by struct literal), gather-only construction authenticated against the injected reader,
pure over reads, fail-closed.

## Phase 1 evidence types

| Type | Proves |
|------|--------|
| `RangeInclusionEvidence` | a content range's leaf is included under a generation root (offline) |
| `RootAnchorEvidence` | a generation root is committed on-chain by the store's launcher-anchored lineage |
| `ReadIntegrityEvidence` | both of the above, bound to the same root — the read→cache→reshare integrity gate |

## The pattern

```rust
use dig_evidence::{Evidence, ReadIntegrityEvidence, ReadIntegrityClaim};

// `chain` is any dig_chainsource_interface::ChainSource (a light client, a full node, a gateway).
let evidence = ReadIntegrityEvidence::gather(&claim, &chain)?; // authenticates against the chain
evidence.verify()?;                                            // offline re-check
// Holding `evidence` witnesses the served range is genuine + anchored → safe to cache + reshare.
```

## Security: the launcher-coin anchor

`RootAnchorEvidence` anchors store identity on the launcher **coin id** (`coin_id == store_id`), never
on a curried `launcher_id` (which is forgeable, #1473). See `SPEC.md` §3.2.

## Install

```toml
[dependencies]
dig-evidence = "0.1"
```

Licensed under either of Apache-2.0 or MIT at your option. See `SPEC.md` for the normative contract.
