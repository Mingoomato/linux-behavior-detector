# Test Results — Linux Ransomware Behavior Detection Lab

Status: the current working tree is unverified. The historical Release, Clang, sanitizer, and selected synthetic results below describe the source before the 512 MiB aggregate input cap, optional CSV/HTML evaluation reports, and bounded rule-correlation analysis were implemented. No builds, tests, schema checks, analyzers, or diff validation have been run for the current changes. Overall SRS verification remains partial; automated results do not establish owner mastery or real-world detection efficacy.

## Environment

- Kali Linux Rolling 2026.3, x86_64; kernel `7.1.5+kali-amd64`.
- GCC 16.2.0; Clang 21.1.8; CMake 4.4.3; OpenSSL 3.6.3.
- Python 3.12 with `jsonschema` 4.26.0 for a separate contract audit.
- C++20, `-Wall -Wextra -Wpedantic -Werror`.

## Build and automated tests

- GCC Release configure/build: passed.
- CTest receives the directory containing its configured bdetect target through BIN_DIR; the GCC, Clang, and ASan/UBSan runs execute their own binaries.
- GCC Release CTest: repeated until-fail three times, 3/3 passed.
- Clang Release configure/build: passed; CTest repeated three times, 3/3 passed.
- Separate AddressSanitizer/UndefinedBehaviorSanitizer build: passed; CTest repeated three times, 3/3 passed.
- `clang++ --analyze -std=c++20 -Wall -Wextra -Wpedantic -Werror -Iinclude src/bdetect.cpp`: passed with no diagnostics.
- Optional Clang 21.1.8 libFuzzer JSON parser target built with AddressSanitizer and UndefinedBehaviorSanitizer; one 100,000-run campaign completed without crash/UB, with 522 coverage counters, 1,904 features, and 139 MiB peak RSS. This was a short selected campaign, not a complete importer/timestamp fuzz audit.
- `git diff --check`: passed.

The optional stats sidecar is also tested for nearest-rank percentile ordering, empty-input null percentiles, input/rule/output alias rejection, and byte-identical decisions with statistics enabled. The focused tests cover 10/30/60-second configured windows and exact left/right boundary inclusion with one-second-outside exclusion for all three durations, in-tolerance event-time reorder, numeric producer sequence ordering despite timestamp reorder, sequence gaps, session reset, conflicting sequence claims, mixed sequence metadata, invalid or incomplete sequence pairs, exact duplicate removal and raw-payload conflicts, late events, all five supported rule operators, configured weight contributions and per-rule source IDs, per-rule minimum samples, degraded coverage, invalid rule operator/window, entity and record bounds, required event fields, duplicate JSON keys, invalid JSON number grammar, invalid UTF-8, valid and invalid Unicode surrogate pairs, RFC 3339 UTC/offset/fraction/leap-day parsing, invalid calendar/missing timezone, exact SHA-256 values, paced/unpaced byte equality, and a one-hour paced-duration guard. Metric tests validate labels/predictions, quoted commas/escaped quotes/embedded newlines, CRLF, malformed quoting, duplicate decoded keys, field bounds, mismatched and duplicate entities, per-rate numerators/denominators, zero denominators, `N/A`, and decision records larger than 1 MiB.

All four JSON Schema Draft 2020-12 files passed `Draft202012Validator.check_schema`. The baseline rules, 296 generated event records, 12 generated decisions, and an actual 100k-run replay-stats sidecar validated against their schemas.

The smoke test generates differentiated synthetic benign and suspicious scenarios, validates and replays them, then evaluates labels. The paired synthetic labels yielded TP=4, FP=0, TN=8, FN=0, unknown=0. These are fixture wiring counts only; the labels were generated with the fixtures and do not estimate real-world performance.

## 100k-event probe

A prior one-second-timestamp probe replayed 100,000 synthetic records in 1.107 seconds with 137,780 KiB peak child RSS and produced one 3,200,655-byte decision. It exercised a large evidence record but did not provide multiple decision-latency samples.

The new multi-window probe used one synthetic host with 100,000 file.modified events spaced two seconds apart, producing 100,000 decisions. The --stats-out sidecar passed Draft 2020-12 validation. In this single run:

- End-to-end replay command wall time, including input hashing/parsing and decision output: 2.471 s.
- evaluate wall time: 993.584 ms.
- Peak child RSS: 195,024 KiB.
- Per-decision scoring latency: p50 6,972 ns, p95 12,643 ns, p99 14,427 ns, maximum 206,368 ns across 100,000 samples.

Per-decision samples cover window scoring and evidence assembly; they exclude parsing, pacing, serialization, and file writes. The measured values describe this synthetic workload on this host. One run is not a repeated performance baseline or a resource guarantee for all allowed inputs.

## Remaining verification gaps

- The optional CSV/HTML report implementation and its prediction-count/timeline limits are unverified. The intended checks are listed in `docs/TEST_PLAN.md` and should be performed only when verification is resumed.
- The `analyze-rules` report implementation and its `bdetect.rule_analysis.v1` schema are unverified. In particular, pair-count arithmetic, phi edge cases, hostile IDs, and the bounded-work refusal path have not been exercised.
- The 512 MiB input-file cap and read-time growth checks have not been exercised. Bounded streaming, TTL eviction, and online watermark semantics remain unimplemented.

- Negative schema-conformance cases and importer/timestamp fuzzing are not complete; generated records, decisions, and the replay-stats sidecar passed their published schemas. The 100,000-run fuzzer targeted the JSON parser only.
- Missing-record detection remains unavailable when upstream events have no producer sequence/session metadata. Sequence audit runs only after full batch load and applies unknown status at host scope; an online lateness watermark and window-scoped gap attribution are not implemented.
- No independently collected or representative benign/security dataset has been evaluated. No frozen, independently held-out dataset, signed manifest, or test-data modification ledger exists yet.
- The rule hash and per-run dataset hash are emitted, but trust/authentication of those hashes is not established.
- Repeated 100k performance baselines and cross-distribution runs remain open; p95 was measured once on the documented synthetic multi-window workload.
- The result does not claim ransomware detection accuracy, endpoint protection, or personal mastery.
