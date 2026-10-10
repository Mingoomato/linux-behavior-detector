# Engineering Study Guide — Linux Ransomware Behavior Detection Lab

## Learning objective and current status

This lab follows synthetic file-event records from input validation to evidence-backed host decisions. Study how event time differs from replay pacing, how the code fails closed to `unknown`, and how configured rule weights become auditable contributions. This is a deterministic simulation, not an endpoint protection product.

Historical GCC/Clang Release builds, focused CTest, and ASan/UBSan checks passed before the dataset freeze/audit commands, input cap, active-window payload release, optional CSV/HTML evaluator reports, and rule-correlation analysis were added. The current working tree is unverified; do not treat those earlier results as applying to it. Historical checks included 10/30/60-second windows, reordering, duplicates, lateness, optional producer sequence gaps and restarts, quoted CSV labels, rule weights, hashes, and paced/unpaced equivalence. One optional 100,000-run Clang libFuzzer campaign exercised the JSON parser under ASan/UBSan without a crash, but it does not establish importer/timestamp fuzz safety. These checks do not prove real-world detection quality, missing-event detection without source sequences, online watermark semantics, holdout integrity, repeated performance baselines, or resource behavior at maximum configured limits. Automated completion is not evidence of owner mastery.

## Why each subsystem exists

| Subsystem | Why it exists | Main code |
|---|---|---|
| Bounded JSON parser | Reject malformed, oversized, deeply nested, or duplicate-key records before feature extraction. | `include/bdetect/json.hpp` |
| Event importer | Convert event.v1 records to owned typed values and preserve line context on errors. | `read_limited_line`, `load_events`, `parse_time` |
| Rule loader | Validate versioned feature/operator/threshold/weight/sample-count rules and hash exact rule bytes. | `load_rules`, `Rule`, `Rules` |
| Normalizer | Deduplicate, identify conflicting IDs, degrade late input, detect optional per-session producer sequence gaps/collisions, enforce entity bounds, and order accepted events. | `normalize_events` |
| Replay clock | Optionally map event-time spacing to monotonic deadlines without letting machine speed change event-time windows or scores. | `pace_replay` |
| Window scorer | Aggregate unique path/extension features and emit configured weighted rule contributions. | `evaluate`, `Decision`, `Reason` |
| Evidence writer and optional performance record | Preserve event IDs, rule/dataset hashes, windows, scores, contributions, coverage, and unknown reasons; optionally record per-decision scoring percentiles. | `write_decisions`, `write_replay_stats` |
| Fixture and metric tools | Produce harmless synthetic input and a confusion-matrix wiring check; parse bounded quoted CSV labels and preserve metric denominators. | `generate_fixtures`, `evaluate_labels`, `read_csv_record` |
| Optional evaluator reports | Export bounded, chronological metric and decision views to quoted CSV or escaped static HTML without including raw file paths. | `evaluate_labels`, `PredictionRecord`, `write_csv_cell`, `html_escape` |
| Rule-correlation analysis | Summarize pair co-activation and contingency counts to highlight possibly redundant rules without changing weights. | `analyze_rule_correlations`, `analyze-rules` |
| Dataset freeze and audit | Keep development and holdout inputs separate by file, bind exact hashes to a rule revision, and append an audit record before evaluation. | `freeze_dataset`, `audit_frozen_dataset`, `write_frozen_manifest`, `append_audit_ledger` |

## Data and control flow

1. `main` dispatches `dataset-freeze`/`dataset-audit`, `rules-validate`, `generate-fixtures`, `replay`, `evaluate`, `analyze-rules`, `explain`, or `validate-events`.
2. Before a holdout run, `dataset-audit` loads the one-record freeze manifest, rehashes the development file, holdout file, and validated rules, appends a match/mismatch record under an exclusive ledger lock, then returns status 1 on mismatch. It records provenance checks; it cannot establish that the holdout was independently collected or never used for tuning.
3. `replay` parses a bounded rules file and hashes its exact bytes. It hashes the input file, parses each JSONL line, and hashes it again to detect a file changed during loading.
4. `load_events` checks UTF-8, event.v1 fields, bounded lengths, and the file/record/event caps. Actor fields are deliberately ignored; an unknown actor stays unknown.
5. `normalize_events` removes exact duplicate IDs, marks conflicts and events outside the lateness tolerance as host-level unknown conditions, checks optional sequence metadata grouped by `(host, source, producer_session_id)`, enforces `max_entities`, and stably sorts by host/time/ID. A new producer session permits sequence reset; a sequence gap or duplicate sequence with different IDs degrades the host. Mixing sequenced and unsequenced records from one host/source also degrades it.
6. Optional `--speed N` builds a global event-time timeline and uses `std::chrono::steady_clock` deadlines. Speed zero skips waiting. It does not alter event-time windows or score calculations.
7. `evaluate` emits an overlapping event-time decision at each distinct event-second endpoint. Per-window sets count unique modified, renamed, deleted, extension, and event values. A matching rule adds its configured weight and a structured reason. Insufficient or degraded evidence yields `unknown`.
8. `write_decisions` serializes source IDs, hashes, window, rule contributions, coverage, and `simulation_only=true`. When `--stats-out` is supplied, `evaluate` records each window's duration using `steady_clock`; `write_replay_stats` emits percentiles to a separate sidecar. It excludes input parsing, pacing, and JSON serialization. `evaluate_labels` joins predictions to CSV labels and computes confusion-matrix rates. Optional CSV/HTML flags retain at most 100,000 compact timeline rows, sort by window end/entity/start, and export actual/predicted labels and outcomes; prediction input itself is capped at one million rows.
9. `analyze-rules` reads only rule IDs from each decision's `reasons[]`, computes marginals and pair contingency counts, then emits Jaccard and phi statistics. It rejects inputs exceeding 512 MiB, 1,000,000 decisions, 256 rules, or ten million pair updates. The output is descriptive; it does not reweight rules and overlapping windows are dependent observations.

## Memory ownership and resource lifetimes

- `load_events` owns a vector of `Event` strings. `normalize_events` copies accepted events to a second vector; both coexist through replay.
- `normalize_events` maps and sets use `std::string_view` keys into the stable input vector. Those views remain valid only while that input vector lives and is not mutated.
- `evaluate` stores non-owning pointers into the normalized vector, which remains alive and immutable for the entire call. Window feature sets own copied strings.
- File streams and the OpenSSL digest context use RAII. The digest context is freed after hashing. No manual descriptor or memory cleanup path is required.
- Freeze and audit helpers use raw file descriptors with explicit close paths. A frozen manifest is created exclusively, changed to mode 0444, and synced. Audit opens a mode 0600 owner-only ledger, serializes appenders with `flock`, and syncs each complete JSONL record. The ledger and manifest are still local files and do not provide signed provenance or protection from an administrator who can replace them.
- Input files are capped at 512 MiB, event JSONL records at 1 MiB, and serialized decision records at 64 MiB. Event/host/rule counts have caps, but windows and output can still approach input cardinality. Requested stats hold one 64-bit latency sample per decision and sort them to calculate exact percentiles, adding O(decisions) memory. Optional reports hold at most 100,000 `PredictionRecord` rows plus strings copied from predictions; prediction parsing stops at 1,000,000 non-empty records. Rule analysis holds at most 256 rule marginals and 10,000,000 co-activation updates. During batch scoring, old event string payloads are released outside the active window, but the event shells, input timeline and indexes are retained. There is no bounded online event queue or watermark/interval TTL yet. Sequence analysis is whole-batch and host-level; it does not implement online gap attribution.

## Linux interfaces, concurrency, and security assumptions

This executable consumes files; it does not call inotify, fanotify, epoll, `openat2`, eBPF, or BPF LSM. C++ file streams own their underlying descriptors and close them at scope exit. `timegm` converts UTC-like broken-down timestamps to seconds. `steady_clock` supplies monotonic deadlines for optional pacing; wall-clock jumps cannot move those deadlines. The application is single-threaded, with no producer/consumer queue or lock protocol.

Treat event, rule, label, and output files as untrusted. Input paths, host identifiers, and event IDs can be sensitive and are emitted in clear text today; keep evidence local. Rules and input hashes prove byte identity only when the recorded digest is trusted; they do not prove dataset representativeness or prevent an attacker from replacing both file and digest. SHA-256 uses OpenSSL EVP. Unknown coverage, lateness, conflicts, and inadequate samples must never be relabeled benign.

Failure modes include malformed/oversized JSON, invalid required fields, rule errors, invalid RFC 3339 dates/offsets, file read/write failures, cardinality limits, invalid speed, and allocation pressure. Fractional seconds are validated but window ordering currently has one-second precision. The offline corpus can use substantial memory before the event-count cap is reached.

## Alternatives and tradeoffs

- The current batch sequence audit is simple and reproducible. A streaming watermark and bounded queue would lower memory use but require explicit gap-finalization, late-event, backpressure, and interval attribution semantics.
- A fully virtual monotonic clock would avoid sleep; the optional paced mode demonstrates monotonic scheduling while the fast default keeps tests quick.
- Generic rule objects are auditable and configurable; their schema and feature vocabulary require strict validation. A learned model could capture interactions but would need independent data and calibration evidence.
- A standards-compliant JSON library would expand parser coverage; the bundled small parser keeps dependencies low but needs fuzz and conformance work.
- A fixed manifest and append-only audit trail make accidental dataset/rule changes visible before evaluation. A signed manifest or remote append-only store would provide stronger provenance, but requires key management and trusted infrastructure outside this lab.
- The optional HTML report is static and has no script dependency; escaped text cells limit markup injection, while an interactive dashboard would need a separate threat model and additional data-handling controls. The current CSV format uses quoted cells and CRLF records for spreadsheet compatibility.
- Pairwise rule co-activation is easy to explain and cheap for sparse active sets; a full matrix becomes expensive with many decisions and rules. Jaccard ignores true negatives, while phi includes them and becomes undefined for constant signals. Neither is causal evidence, and adjacent overlapping windows are not independent. The work cap rejects overly dense analyses rather than silently truncating results.
- Dataset manifests and immutable development/holdout splits would strengthen reproducibility. Per-run input hashes alone do not supply that separation.

## Study route

Read `docs/ARCHITECTURE.md`, then trace `dataset-freeze` → `dataset-audit` before tracing `main` → `load_rules`/`load_events` → `normalize_events` → `pace_replay` → `evaluate` → `write_decisions`. Reconstruct one score from `reasons[]`; trace `evaluate_labels` into metric rows, CSV quoting, and HTML escaping, then follow `analyze-rules` from reason IDs to pair counts. The recent freeze/audit, cap, report, and analysis changes have not been technically verified. Then attempt one task from `docs/DEBUGGING_EXERCISES.md` independently and defend your design with `docs/TECHNICAL_INTERVIEW.md`.

## Official references

- [C++ `std::chrono::steady_clock`](https://en.cppreference.com/w/cpp/chrono/steady_clock.html) and [C++ file streams](https://en.cppreference.com/w/cpp/io/basic_ifstream.html)
- [OpenSSL EVP digest API](https://docs.openssl.org/3.0/man3/EVP_DigestInit/)
- [LLVM libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html)
- [Linux `timegm(3)`](https://man7.org/linux/man-pages/man3/timegm.3.html) and [`clock_gettime(2)`](https://man7.org/linux/man-pages/man2/clock_gettime.2.html)
- Linux [`open(2)`](https://man7.org/linux/man-pages/man2/open.2.html), [`flock(2)`](https://man7.org/linux/man-pages/man2/flock.2.html), [`fsync(2)`](https://man7.org/linux/man-pages/man2/fsync.2.html), [`fdatasync(2)`](https://man7.org/linux/man-pages/man2/fdatasync.2.html), and [`fchmod(2)`](https://man7.org/linux/man-pages/man2/fchmod.2.html)
- [RFC 8259 — JSON](https://www.rfc-editor.org/rfc/rfc8259), [RFC 4180 — CSV format](https://www.rfc-editor.org/rfc/rfc4180), [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12)
- [Linux inotify documentation](https://docs.kernel.org/filesystems/inotify.html) and [`inotify(7)`](https://man7.org/linux/man-pages/man7/inotify.7.html) for possible upstream collectors; neither is implemented here.
