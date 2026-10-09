# Debugging and Independent Reproduction Exercises

These exercises are unsolved. No solution patch is included before an attempt. Use synthetic records only; do not run malware or use personal telemetry.

## Exercise 1 — Detecting missing events without inventing evidence

**Goal:** Extend event provenance so a dropped source record can be detected when the producer supports sequencing.

**Starting points:** `Event`, `load_events`, `normalize_events`, the event.v1 producer contract, and `docs/TEST_PLAN.md`.

Define an optional per-source sequence field and its reset/session semantics. Create records with a continuous sequence, a gap, a restart, and a duplicate. Mark only the affected source/host interval unknown when a gap is proven; absence of a sequence field must remain “not observable,” not a fabricated gap.

**Constraints:** Keep record and total-event limits. Never infer an actor or assume sequence numbers are globally unique across hosts/sessions. Do not convert out-of-order or degraded evidence into benign.

**Acceptance:** Tests distinguish a proven sequence gap from unavailable sequence metadata, and repeated replays produce identical unknown/degraded intervals.

## Exercise 2 — Rule contribution and rule hash

**Goal:** Make each decision traceable to a versioned rule set and its actual configured contribution.

**Starting points:** `Rules`, `load_rules`, `evaluate`, `write_decisions`, and `contracts/decision-v1.schema.json`.

Add tests where thresholds and weights differ from baseline, validate negative/oversized values, record a stable cryptographic hash of the exact rule file, and include observed value, threshold, and weight for each contributing rule.

**Constraints:** Preserve `simulation_only=true`. Reject unsupported or malformed rule entries. Do not tune thresholds against validation fixtures.

**Acceptance:** A reviewer can reconstruct each score from evidence, and changing rule-file bytes changes its recorded hash.

## Exercise 3 — Honest confusion-matrix evaluation

**Goal:** Make metric denominators and label errors explicit.

**Starting points:** `evaluate_labels` and generated `labels.csv`.

Add fixtures for an invalid label, unknown prediction, missing/extra entities, a CSV field containing a comma or quote, and a zero-denominator class. Define whether unknowns count separately or in a rate denominator and include that rule in tests and report output.

**Constraints:** Reject invalid labels instead of silently treating any non-suspicious label as benign. Keep fixture metrics labeled as synthetic-only.

**Acceptance:** The report contains counts and denominators behind every rate, emits `N/A` for zero denominator, and identifies label-set mismatches.

## Owner attempt record

Record the exercise, design choices, tests, and unresolved cases in personal notes. Repository build/test completion does not prove mastery; owner reproduction is **not yet evidenced**.
