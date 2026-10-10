# Debugging and Independent Reproduction Exercises

These three exercises are intentionally unsolved. The repository contains no answer key or complete patch. Work only with synthetic records; do not run malware or process personal telemetry. Completing an exercise is separate from automated repository verification.

## Exercise 1 — Make decision output crash-safe

**Goal:** Prevent an interrupted or failed `write_decisions` run from leaving a truncated file that looks like a complete result.

**Starting points:** `write_decisions`, `main`, `docs/THREAT_MODEL.md`, and the decision output contract.

Design a temporary-file protocol in the destination directory, define when the old file is retained, and add synthetic tests for serialization failure and replacement failure. Consider concurrent readers and an already existing destination.

**Constraints:** Preserve deterministic bytes and existing file permissions deliberately; do not follow a symlink outside the intended output path; do not claim power-loss durability unless file and directory synchronization are handled and tested. Keep the output schema unchanged.

**Acceptance:** A failed write leaves the previous complete result intact (or no result if none existed), successful replacement yields a complete valid JSONL file, and tests pass under sanitizers.

## Exercise 2 — Add a negative schema-conformance matrix

**Goal:** Test that every published event, rule, and decision schema rejects representative invalid values as well as accepting valid fixtures.

**Starting points:** `contracts/*.schema.json`, generated fixture output, `docs/TEST_PLAN.md`, and a Draft 2020-12 validator.

Create table-driven invalid records for missing paired metadata, wrong scalar types, out-of-range integers, invalid enum values, bad nested structures, and unexpected decision flags. Record which checks belong to JSON Schema and which require application-level validation.

**Constraints:** Keep Draft 2020-12 semantics, event line numbers, synthetic-only data, and the distinction between schema validity and semantic trust. Do not add a schema-validation runtime dependency to the normal executable.

**Acceptance:** Positive and negative cases run deterministically, report the schema/property responsible for rejection, and remain separate from parser fuzz results.

## Exercise 3 — Add an auditable CSV metrics report

**Goal:** Add an optional CSV output for the confusion matrix and rates while keeping the current JSON report available.

**Starting points:** `evaluate_labels`, the `evaluate` CLI dispatch, `docs/TEST_PLAN.md`, and the existing JSON report fields.

Define stable columns for each metric, its numerator, denominator, value, and unknown predictions. Add synthetic valid and zero-denominator cases, then verify that quoting and line endings remain valid for CSV consumers.

**Constraints:** Keep existing JSON output byte-compatible, preserve `N/A` for zero denominators, keep unknown separate from TP/FP/TN/FN, and do not disclose raw paths or extra prediction evidence.

**Acceptance:** JSON and CSV outputs report identical counts/rates; tests cover normal and zero-denominator cases and parse the CSV report with a standard reader.

## Owner attempt record

Record the selected exercise, independent design, tests, and unresolved cases in personal notes. Repository build/test completion does not prove personal mastery. Owner study and reproduction status remains **unassessed** until direct evidence is supplied.
