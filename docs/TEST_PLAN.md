# Test Plan

- Verify JSON line size/schema, duplicate keys, malformed escapes and UTF-8, timestamps, missing fields, and line-number diagnostics.
- Replay identical fixture sets at different pacing speeds and compare output bytes; verify exact rule/dataset digests.
- Test 10/30/60-second windows, exact boundaries, in-tolerance event-time reorder, duplicate removal, too-late/conflicting IDs, actor unknown state, sample limits, and degraded coverage. Exercise optional producer session/sequence metadata: gaps, numeric order despite timestamp reorder, restart reset, sequence collision, mixed metadata, and pair/range validation.
- Generate eight benign and four suspicious synthetic scenarios in a new sandbox; inspect rule evidence and calculate synthetic-only confusion metrics.
- Test supported rule operators and bounds, label validation/denominators, quoted CSV keys and multiline fields, malformed quoting and bounds, malformed rules, and output errors.
- For `evaluate --csv-report` and `--html-report`, compare counts/rates with JSON, verify unknown remains separate, assert chronological decision order and omission of raw paths, test hostile HTML text escaping, quoted CSV cells with CRLF, output-path alias rejection, missing/invalid window fields, zero-denominator `N/A`, and the 100,000-row timeline cap.
- For `analyze-rules`, verify pair contingency counts, Jaccard and phi values for identical/disjoint/partially co-active rules, repeated reasons within one decision, empty input, malformed reason arrays, output alias rejection, and each decision/rule/pair-update limit. Validate the output against `contracts/rule-analysis-v1.schema.json`; explicitly document that overlapping windows are dependent.
- Exercise 512 MiB aggregate file-size refusal and read-time growth refusal for event, prediction, and rule-analysis inputs; test exact-boundary acceptance using sparse synthetic data without allocating an unbounded corpus.
- Check event payload lifetime at 10/30/60-second window expiration and large time jumps; ensure copied evidence for emitted decisions remains available after expired event strings are released.
- Verify `--stats-out` percentiles and schema, empty-result nulls, refusal of input/rule/output path aliases, and byte-identical decision JSONL with stats enabled.
- Measure 100k records, peak RSS, p95 decision latency, and runtime on a documented machine.

## Current evidence

Historical Release, Clang, ASan/UBSan, static analysis, positive JSON Schema validation for generated event/rule/decision records, selected timestamp/rule/replay checks, quoted-CSV label/denominator checks, exact 10/30/60-second window boundary cases, a 100k-record wall-time/RSS/p95 probe, stats-sidecar percentile and alias checks, and one 100k-run Clang libFuzzer parser campaign were run against the earlier source revision. No verification has been run against the current working tree after the optional CSV/HTML report and rule-correlation analysis implementations were added. Negative schema coverage, importer/timestamp fuzzing, report output cases listed above, independent holdout integrity, and cross-distribution verification remain pending. Sequence validation has historical focused application-level cases; online watermark semantics and window-scoped gap attribution remain open. See `docs/TEST_RESULTS.md` for the exact scope and limits.
