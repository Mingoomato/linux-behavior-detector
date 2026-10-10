# Debugging and Independent Reproduction Exercises

These three exercises are intentionally unsolved. The repository contains no answer key or complete patch. Work only with synthetic records; do not run malware or process personal telemetry. Completing an exercise is separate from automated repository verification.

## Exercise 1 — Prove a missing source event

**Goal:** Extend provenance so a dropped source record can be detected only when a producer supports sequencing.

**Starting points:** `Event`, `load_events`, `normalize_events`, the event.v1 contract, and `docs/TEST_PLAN.md`.

Define an optional per-source sequence field and reset/session semantics. Add synthetic continuous, gapped, restarted, and duplicated sequences. Mark only the affected host/source interval unknown when a gap is provable. A source without sequence metadata must remain “not observable.”

**Constraints:** Preserve the record/event limits; do not treat a sequence as globally unique across hosts or producer sessions; do not infer an actor; do not downgrade degraded evidence to benign.

**Acceptance:** Tests distinguish a proven gap, a producer restart, a duplicate, and unavailable sequence metadata. Identical input and rules produce identical affected intervals.

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
