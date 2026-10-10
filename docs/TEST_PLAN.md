# Test Plan

- Verify JSON line size/schema, duplicate keys, malformed escapes and UTF-8, timestamps, missing fields, and line-number diagnostics.
- Replay identical fixture sets at different pacing speeds and compare output bytes; verify exact rule/dataset digests.
- Test 10/30/60-second windows, exact boundaries, in-tolerance event-time reorder, duplicate removal, too-late/conflicting IDs, actor unknown state, sample limits, and degraded coverage. Exercise optional producer session/sequence metadata: gaps, numeric order despite timestamp reorder, restart reset, sequence collision, mixed metadata, and pair/range validation.
- Generate eight benign and four suspicious synthetic scenarios in a new sandbox; inspect rule evidence and calculate synthetic-only confusion metrics.
- Test supported rule operators and bounds, label validation/denominators, quoted CSV keys and multiline fields, malformed quoting and bounds, malformed rules, and output errors.
- Verify `--stats-out` percentiles and schema, empty-result nulls, refusal of input/rule/output path aliases, and byte-identical decision JSONL with stats enabled.
- Measure 100k records, peak RSS, p95 decision latency, and runtime on a documented machine.

## Current evidence

Release, Clang, ASan/UBSan, static analysis, positive JSON Schema validation for generated event/rule/decision records, selected timestamp/rule/replay checks, quoted-CSV label/denominator checks, exact 10/30/60-second window boundary cases, a 100k-record wall-time/RSS/p95 probe, stats-sidecar percentile and alias checks, and one 100k-run Clang libFuzzer parser campaign have run. Negative schema coverage, importer/timestamp fuzzing, p95 decision latency, independent holdout integrity, and cross-distribution verification remain pending. Sequence validation now has focused application-level cases; online watermark semantics and window-scoped gap attribution remain open. See `docs/TEST_RESULTS.md` for measured values and limits.
