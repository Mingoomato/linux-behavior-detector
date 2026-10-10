# Debugging and Independent Reproduction Exercises

These three exercises are intentionally unsolved. The repository contains no answer key or complete patch. Work only with synthetic records; do not run malware or process personal telemetry. Completing an exercise is separate from automated repository verification.

## Exercise 1 — Verify decision source hashes

**Goal:** Add an `explain --verify-hashes` mode that checks the selected decision's dataset and ruleset digests against explicitly supplied source files before printing it.

**Starting points:** `main`'s `explain` branch, `load_rules`, `sha256_file`, the decision output contract, and `contracts/decision-v1.schema.json`.

Define how the CLI handles a missing expected source, malformed decision record, unsupported schema, and either digest mismatch. Decide whether scanning stops at the first matching ID or rejects duplicate decision IDs in the input. Preserve normal `explain` behavior when verification is not requested.

**Constraints:** Do not treat matching hashes as proof that the source or labels are trustworthy. Keep the verification read-only and do not modify the decision file or the rules. Use synthetic data and do not load real telemetry.

**Acceptance:** Matching files allow the chosen record to print; a changed dataset or rules file, wrong revision/hash, duplicate target ID according to your chosen policy, and malformed decision input produce a clear nonzero result. Existing non-verifying `explain` remains compatible.

## Exercise 2 — Add a negative schema-conformance matrix

**Goal:** Test that every published event, rule, and decision schema rejects representative invalid values as well as accepting valid fixtures.

**Starting points:** `contracts/*.schema.json`, generated fixture output, `docs/TEST_PLAN.md`, and a Draft 2020-12 validator.

Create table-driven invalid records for missing paired metadata, wrong scalar types, out-of-range integers, invalid enum values, bad nested structures, and unexpected decision flags. Record which checks belong to JSON Schema and which require application-level validation.

**Constraints:** Keep Draft 2020-12 semantics, event line numbers, synthetic-only data, and the distinction between schema validity and semantic trust. Do not add a schema-validation runtime dependency to the normal executable.

**Acceptance:** Positive and negative cases run deterministically, report the schema/property responsible for rejection, and remain separate from parser fuzz results.

## Exercise 3 — Finalize producer sequence gaps online

**Goal:** Extend `replay --stream` to consume optional producer session/sequence metadata and make bounded, window-scoped gap decisions without buffering the full input.

**Starting points:** the batch `(host, source, producer_session_id)` sequence audit, `stream_replay`, its watermark queue and `issue_until`, and `docs/ARCHITECTURE.md`.

Specify how session restarts, duplicate sequence numbers, mixed sequenced/unsequenced sources, and sequence gaps interact with event-time disorder. Bound any per-source sequence state and define when a missing sequence becomes final. Decide how gap status propagates across overlapping windows and when that metadata expires.

**Constraints:** Do not claim a missing event when the producer supplies no sequence metadata. Do not evict evidence still needed by an open window. Keep actor attribution unknown and preserve the rule that degraded coverage cannot become benign. Use only synthetic event fixtures.

**Acceptance:** Memory use is bounded by documented queue/feature limits; synthetic cases cover session restart, gaps, duplicate/colliding sequence values, mixed metadata, watermark boundaries, overflow, TTL expiry, and unknown propagation. Do not reveal a full solution before the owner attempts the exercise.

## Owner attempt record

Record the selected exercise, independent design, tests, and unresolved cases in personal notes. Repository build/test completion does not prove personal mastery. Owner study and reproduction status remains **unassessed** until direct evidence is supplied.
