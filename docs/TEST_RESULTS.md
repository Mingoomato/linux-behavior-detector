# Test Results — Linux Ransomware Behavior Detection Lab

Status: the local Release, Clang, sanitizer, and selected synthetic verification gates pass. Overall SRS verification remains partial; this is not evidence of owner mastery or real-world detection efficacy.

## Environment

- Kali Linux Rolling 2026.3, x86_64; kernel `7.1.5+kali-amd64`.
- GCC 16.2.0; Clang 21.1.8; CMake 4.4.3; OpenSSL 3.6.3.
- Python 3.12 with `jsonschema` 4.26.0 for a separate contract audit.
- C++20, `-Wall -Wextra -Wpedantic -Werror`.

## Build and automated tests

- GCC Release configure/build: passed.
- GCC Release CTest: repeated until-fail three times, 3/3 passed.
- Clang Release configure/build: passed; CTest repeated three times, 3/3 passed.
- Separate AddressSanitizer/UndefinedBehaviorSanitizer build: passed; CTest repeated three times, 3/3 passed.
- `clang++ --analyze -std=c++20 -Wall -Wextra -Wpedantic -Werror -Iinclude src/bdetect.cpp`: passed with no diagnostics.
- `git diff --check`: passed.

The focused tests cover 10/30/60-second configured windows and exact left/right boundary inclusion with one-second-outside exclusion for all three durations, in-tolerance event-time reorder, numeric producer sequence ordering despite timestamp reorder, sequence gaps, session reset, conflicting sequence claims, mixed sequence metadata, invalid or incomplete sequence pairs, exact duplicate removal and raw-payload conflicts, late events, all five supported rule operators, configured weight contributions and per-rule source IDs, per-rule minimum samples, degraded coverage, invalid rule operator/window, entity and record bounds, required event fields, duplicate JSON keys, invalid JSON number grammar, invalid UTF-8, valid and invalid Unicode surrogate pairs, RFC 3339 UTC/offset/fraction/leap-day parsing, invalid calendar/missing timezone, exact SHA-256 values, paced/unpaced byte equality, and a one-hour paced-duration guard. Metric tests validate labels/predictions, quoted commas/escaped quotes/embedded newlines, CRLF, malformed quoting, duplicate decoded keys, field bounds, mismatched and duplicate entities, per-rate numerators/denominators, zero denominators, `N/A`, and decision records larger than 1 MiB.

All three JSON Schema Draft 2020-12 files passed `Draft202012Validator.check_schema`. The baseline rules, 296 generated event records, and 12 generated decisions validated against their corresponding schemas.

The smoke test generates differentiated synthetic benign and suspicious scenarios, validates and replays them, then evaluates labels. The paired synthetic labels yielded TP=4, FP=0, TN=8, FN=0, unknown=0. These are fixture wiring counts only; the labels were generated with the fixtures and do not estimate real-world performance.

## 100k-event probe

One run replayed 100,000 synthetic records (35,300,000 input bytes) on this host in 1.107 seconds with a maximum child RSS of 137,780 KiB. It produced one 3,200,655-byte decision for the single-host/single-second dataset; the subsequent `evaluate` command parsed that large evidence record successfully. The executable does not measure or report p95 per-decision latency, so that SRS metric is **not measured**. This single run is not a stable performance baseline and does not verify every NFR-03 criterion.

## Remaining verification gaps

- Negative schema-conformance cases and parser fuzzing are not complete; generated records and decisions passed the published schemas.
- Missing-record detection remains unavailable when upstream events have no producer sequence/session metadata. Sequence audit runs only after full batch load and applies unknown status at host scope; an online lateness watermark and window-scoped gap attribution are not implemented.
- No independently collected or representative benign/security dataset has been evaluated. No frozen, independently held-out dataset, signed manifest, or test-data modification ledger exists yet.
- The rule hash and per-run dataset hash are emitted, but trust/authentication of those hashes is not established.
- 100k p95 decision latency, repeated performance baselines, and cross-distribution runs remain open.
- The result does not claim ransomware detection accuracy, endpoint protection, or personal mastery.
