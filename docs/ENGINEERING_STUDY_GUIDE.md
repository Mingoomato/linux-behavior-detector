# Engineering Study Guide — Linux Ransomware Behavior Detection Lab

## Learning objective and implementation status

This lab demonstrates a deterministic pipeline from synthetic file-event records to explainable host-level decisions. Its purpose is to teach event validation, time grouping, feature aggregation, rule evaluation, provenance, and metric interpretation without executing ransomware or touching real user files. It must always be presented as a simulation; fixture performance is not a real-world detection rate.

Release build and the synthetic fixture CTest passed on the current Linux host. A separate ASan/UBSan smoke run is recorded as passed. The fixtures produced TP=4, FP=0, TN=8, FN=0, but generated labels and events are paired, so this only verifies pipeline wiring. Implementation remains partial against SRS-02: current windows are fixed UTC buckets rather than a sliding/lateness-aware replay; duplicate IDs are not removed before minimum-sample evaluation; configured weights are not fully applied; development/validation data are not frozen separately; path pseudonymization and 100k-event measurements are absent; parser fuzzing is unverified.

## Why the subsystems exist

| Subsystem | Purpose | Code |
|---|---|---|
| Bounded JSON reader | Reject malformed, deeply nested, duplicate-key, or oversized JSON before field use. | `include/bdetect/json.hpp` |
| Event importer | Converts event.v1 records into typed values and adds line-number context to failures. | `load_events`, `parse_time` |
| Rules loader | Applies a version and basic numeric bounds to the lab rule set. | `load_rules` |
| Time/window aggregator | Groups evidence by host and time bucket, counting unique paths and extensions. | `evaluate` |
| Explainable scorer | Emits named rule reasons and `unknown` when coverage or sample count is insufficient. | `evaluate`, `Decision` |
| Decision serializer | Keeps `simulation_only`, source event IDs, rule revision, coverage, and unknown fields visible. | `write_decisions` |
| Fixture/evaluation tools | Reproduces benign/suspicious synthetic scenarios and computes a confusion matrix. | `generate_fixtures`, `evaluate_labels` |

## Data and control flow

1. `main` chooses `rules-validate`, `generate-fixtures`, `replay`, `evaluate`, `explain`, or `validate-events`.
2. Replay calls `load_events`; each JSONL line is parsed independently, checked for `schema_version=event.v1`, required identifiers, target path, coverage, and timestamp. Errors are wrapped with a one-based input line number.
3. `load_rules` parses a `rules.v1` object and checks selected numeric bounds.
4. `evaluate` computes an epoch-second bucket for every event and groups pointers under `(host_id, bucket-start)`. Sets deduplicate path counts and event IDs within each bucket. Degraded/unsupported coverage or insufficient sample count yields `unknown`; otherwise feature thresholds add named reasons and a score cutoff yields benign/suspicious.
5. `write_decisions` emits one record per bucket. `evaluate_labels` joins `entity_key` to CSV labels and writes counts and rates. `explain` retrieves a serialized decision by ID.

## Ownership, lifetime, and concurrency

- `load_events` owns a `std::vector<Event>`; its strings own their storage. `evaluate` stores non-owning pointers into that vector, valid while the vector remains alive and unmodified.
- Maps and sets own copies of host, path, extension, and event-ID strings. Memory grows with input size and unique paths; streaming retention and all entity bounds are not fully implemented.
- `std::ifstream`/`std::ofstream` close files through RAII. The program is single-threaded and has no shared mutable worker queue.
- Determinism comes from reading the whole corpus and ordered `std::map` keys, not from a streaming monotonic clock. Event timestamps control grouping.

## Security assumptions and failure modes

Treat event files, rules, labels, and output paths as untrusted. The JSON parser bounds a record and nesting, but full standards conformance, invalid UTF-8 rejection, and fuzz coverage are not established. Input paths and host IDs may be personal data and are currently emitted without full pseudonymization. Large valid inputs can still use considerable CPU and aggregate memory within current cardinality limits.

Malformed records fail with a line number. Degraded/unsupported coverage produces `unknown`, avoiding a false benign claim. However, fixed windows can split bursts, configured lateness is not fully applied, and duplicate records can inflate the minimum sample count. Metrics are meaningful only if labels are valid, representative, and separated from tuning data.

## Alternatives and tradeoffs

- A **sliding event-time window** captures bursts across fixed boundaries but needs a watermark, late-event policy, bounded retention, and deterministic flush behavior.
- A **streaming monotonic replay clock** separates processing speed from event time; sorting an offline file is simpler but uses more memory and hides arrival-time behavior.
- **Rule objects** with ID, feature, operator, threshold, weight, and minimum count are easier to audit than hard-coded branches, but need strict schema validation and versioning.
- A **JSON Schema library** broadens standards validation; the local parser reduces dependencies but has a narrower tested surface.
- Machine learning and content-entropy features are deliberately outside this deterministic baseline and would require separate data-quality and false-positive studies.

## Study route

Read `docs/ARCHITECTURE.md`, then trace `replay` through `load_events` → `load_rules` → `evaluate` → `write_decisions`. Follow one fixture to the confusion matrix. Use `docs/CODE_WALKTHROUGH.md` and `docs/LINUX_INTERNALS_EXPLAINED.md`; attempt one task in `docs/DEBUGGING_EXERCISES.md` before requesting a solution review.

## Official references

- [Linux kernel inotify documentation](https://docs.kernel.org/filesystems/inotify.html) and [`inotify(7)`](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [C++ `std::chrono`](https://en.cppreference.com/w/cpp/chrono.html) and [C++ file streams](https://en.cppreference.com/w/cpp/io/basic_ifstream.html)
- [RFC 8259 — JSON](https://www.rfc-editor.org/rfc/rfc8259)
- [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12)
- [NIST SP 800-218 SSDF](https://csrc.nist.gov/pubs/sp/800/218/final)
