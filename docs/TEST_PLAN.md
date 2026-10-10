# Test Plan

- Verify JSON line size/schema, duplicate keys, malformed escapes and UTF-8, timestamps, missing fields, and line-number diagnostics.
- Replay identical fixture sets at different pacing speeds and compare output bytes; verify exact rule/dataset digests.
- Test 10/30/60-second windows, exact boundaries, in-tolerance reorder, duplicate removal, too-late/conflicting IDs, actor unknown state, sample limits, and degraded coverage.
- Generate eight benign and four suspicious synthetic scenarios in a new sandbox; inspect rule evidence and calculate synthetic-only confusion metrics.
- Test supported rule operators and bounds, label validation/denominators, malformed rules, and output errors.
- Measure 100k records, peak RSS, p95 decision latency, and runtime on a documented machine.

## Current evidence

Release, Clang, ASan/UBSan, static analysis, positive JSON Schema validation for generated event/rule/decision records, selected timestamp/rule/replay checks, label/denominator checks, and a 100k-record wall-time/RSS probe have run. Negative schema coverage, exact 30/60-second boundaries, fuzzing, RFC 4180 quoted-label handling, p95 decision latency, independent holdout integrity, and cross-distribution verification remain pending. See `docs/TEST_RESULTS.md` for measured values and limits.
