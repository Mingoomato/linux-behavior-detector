# Debugging and Independent Reproduction Exercises

These three exercises are intentionally unsolved. The repository contains no answer key or complete patch. Work only with synthetic records; do not run malware or process personal telemetry. Completing an exercise is separate from automated repository verification.

## Exercise 1 — Make decision output crash-safe

**Goal:** Prevent an interrupted or failed `write_decisions` run from leaving a truncated file that looks like a complete result.

**Starting points:** `write_decisions`, `main`, `docs/THREAT_MODEL.md`, and the decision output contract.

Design a temporary-file protocol in the destination directory, define when the old file is retained, and add synthetic tests for serialization failure and replacement failure. Consider concurrent readers and an already existing destination.

**Constraints:** Preserve deterministic bytes and existing file permissions deliberately; do not follow a symlink outside the intended output path; do not claim power-loss durability unless file and directory synchronization are handled and tested. Keep the output schema unchanged.

**Acceptance:** A failed write leaves the previous complete result intact (or no result if none existed), successful replacement yields a complete valid JSONL file, and tests pass under sanitizers.

## Exercise 2 — Fuzz the JSON and timestamp boundary

**Goal:** Add a parser fuzz target that explores malformed JSON and timestamps without process crashes, undefined behavior, or unbounded record growth.

**Starting points:** `include/bdetect/json.hpp`, `load_events`, `parse_time`, `CMakeLists.txt`, and `tests/window_replay.py`.

Create a fuzz harness for the parser/import boundary and seed it with duplicate keys, nesting limits, malformed escapes, invalid UTF-8, oversized fields, offsets, fractions, invalid dates, and missing timezone markers. Make the harness reusable under a supported coverage-guided fuzzer and sanitizer build.

**Constraints:** Keep the 1 MiB record cap and line-numbered failures. Do not add a runtime dependency to normal release builds. Keep fuzz-generated data synthetic.

**Acceptance:** The harness builds with sanitizers, a bounded fuzz session completes without crash/UB, and saved regression cases remain in deterministic tests.

## Exercise 3 — Support quoted CSV labels safely

**Goal:** Replace the deliberately minimal label reader with a correct, bounded CSV parser that handles quoted entity keys and rejects malformed quoting.

**Starting points:** `evaluate_labels`, generated `labels.csv`, and `docs/TEST_PLAN.md`.

Support commas, escaped quotes, and quoted newlines according to the chosen CSV dialect. Add synthetic inputs with valid quoted keys, malformed quote placement, trailing columns, duplicate keys, and line-ending variations. Keep the existing numerator/denominator fields and explicit unknown count intact.

**Constraints:** Keep total file/field sizes bounded, reject invalid labels instead of treating every non-suspicious value as benign, and do not let CSV quoting change which entity is joined to a prediction.

**Acceptance:** Quoted keys round-trip exactly; malformed CSV fails with a line number; all current metric-validation tests continue to pass.

## Owner attempt record

Record the selected exercise, independent design, tests, and unresolved cases in personal notes. Repository build/test completion does not prove personal mastery. Owner study and reproduction status remains **unassessed** until direct evidence is supplied.
