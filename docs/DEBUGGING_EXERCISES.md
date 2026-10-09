# Debugging and Independent Reproduction Exercises

These exercises are unsolved. No solution patch is included before an attempt. Use synthetic records only; do not run malware or use personal telemetry.

## Exercise 1 — Duplicate and late event handling

**Goal:** Make sample counts and decisions robust to duplicate IDs and out-of-order timestamps.

**Starting points:** `load_events`, `parse_time`, `evaluate`, `lateness_tolerance_ms` in `rules/baseline.json`, and `docs/TEST_PLAN.md`.

Create a small JSONL corpus with one duplicate ID, events inside the lateness tolerance, and one event outside it. Define the exact policy for duplicate and late records, preserve unknown coverage when evidence cannot be trusted, and add deterministic regression tests.

**Constraints:** Keep record and total-event limits. Never infer an actor. Do not convert out-of-order or degraded evidence into benign.

**Acceptance:** Repeated runs yield normalized identical output; each source ID follows the documented policy; the outside-tolerance record is represented explicitly.

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
