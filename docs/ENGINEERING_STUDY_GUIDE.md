# Engineering Study Guide — Linux Ransomware Behavior Detection Lab

## Learning objective and current status

This lab follows synthetic file-event records from input validation to evidence-backed host decisions. Study how event time differs from replay pacing, how the code fails closed to `unknown`, and how configured rule weights become auditable contributions. This is a deterministic simulation, not an endpoint protection product.

The Release build and focused CTest pass on the current Linux host. The focused test checks 10/30/60-second windows, reordering, duplicates, lateness, rule weights, hashes, and paced/unpaced equivalence. It does not prove real-world detection quality, missing-event detection without source sequences, holdout integrity, parser fuzz safety, or the 100k performance target. Automated completion is not evidence of owner mastery.

## Why each subsystem exists

| Subsystem | Why it exists | Main code |
|---|---|---|
| Bounded JSON parser | Reject malformed, oversized, deeply nested, or duplicate-key records before feature extraction. | `include/bdetect/json.hpp` |
| Event importer | Convert event.v1 records to owned typed values and preserve line context on errors. | `read_limited_line`, `load_events`, `parse_time` |
| Rule loader | Validate versioned feature/operator/threshold/weight/sample-count rules and hash exact rule bytes. | `load_rules`, `Rule`, `Rules` |
| Normalizer | Deduplicate, identify conflicting IDs, degrade late input, enforce entity bounds, and order accepted events. | `normalize_events` |
| Replay clock | Optionally map event-time spacing to monotonic deadlines without letting machine speed change event-time windows or scores. | `pace_replay` |
| Window scorer | Aggregate unique path/extension features and emit configured weighted rule contributions. | `evaluate`, `Decision`, `Reason` |
| Evidence writer | Preserve event IDs, rule and dataset hashes, window, score, rule contributions, coverage, and unknown reasons. | `write_decisions` |
| Fixture and metric tools | Produce harmless synthetic input and a confusion-matrix wiring check. | `generate_fixtures`, `evaluate_labels` |

## Data and control flow

1. `main` dispatches `rules-validate`, `generate-fixtures`, `replay`, `evaluate`, `explain`, or `validate-events`.
2. `replay` parses a bounded rules file and hashes its exact bytes. It hashes the input file, parses each JSONL line, and hashes it again to detect a file changed during loading.
3. `load_events` checks UTF-8, event.v1 fields, bounded lengths, and the record/event caps. Actor fields are deliberately ignored; an unknown actor stays unknown.
4. `normalize_events` removes exact duplicate IDs, marks conflicts and events outside the lateness tolerance as host-level unknown conditions, enforces `max_entities`, and stably sorts by host/time/ID.
5. Optional `--speed N` builds a global event-time timeline and uses `std::chrono::steady_clock` deadlines. Speed zero skips waiting. It does not alter event-time windows or score calculations.
6. `evaluate` emits an overlapping event-time decision at each distinct event-second endpoint. Per-window sets count unique modified, renamed, deleted, extension, and event values. A matching rule adds its configured weight and a structured reason. Insufficient or degraded evidence yields `unknown`.
7. `write_decisions` serializes source IDs, hashes, window, rule contributions, coverage, and `simulation_only=true`. `evaluate_labels` joins predictions to CSV labels and computes confusion-matrix rates.

## Memory ownership and resource lifetimes

- `load_events` owns a vector of `Event` strings. `normalize_events` copies accepted events to a second vector; both coexist through replay.
- `normalize_events` maps and sets use `std::string_view` keys into the stable input vector. Those views remain valid only while that input vector lives and is not mutated.
- `evaluate` stores non-owning pointers into the normalized vector, which remains alive and immutable for the entire call. Window feature sets own copied strings.
- File streams and the OpenSSL digest context use RAII. The digest context is freed after hashing. No manual descriptor or memory cleanup path is required.
- Input JSONL records are capped at 1 MiB; serialized decision records are capped at 64 MiB. Event/host/rule counts have caps, but windows and output can still approach input cardinality. There is no streaming queue or TTL eviction yet.

## Linux interfaces, concurrency, and security assumptions

This executable consumes files; it does not call inotify, fanotify, epoll, `openat2`, eBPF, or BPF LSM. C++ file streams own their underlying descriptors and close them at scope exit. `timegm` converts UTC-like broken-down timestamps to seconds. `steady_clock` supplies monotonic deadlines for optional pacing; wall-clock jumps cannot move those deadlines. The application is single-threaded, with no producer/consumer queue or lock protocol.

Treat event, rule, label, and output files as untrusted. Input paths, host identifiers, and event IDs can be sensitive and are emitted in clear text today; keep evidence local. Rules and input hashes prove byte identity only when the recorded digest is trusted; they do not prove dataset representativeness or prevent an attacker from replacing both file and digest. SHA-256 uses OpenSSL EVP. Unknown coverage, lateness, conflicts, and inadequate samples must never be relabeled benign.

Failure modes include malformed/oversized JSON, invalid required fields, rule errors, invalid RFC 3339 dates/offsets, file read/write failures, cardinality limits, invalid speed, and allocation pressure. Fractional seconds are validated but window ordering currently has one-second precision. The offline corpus can use substantial memory before the event-count cap is reached.

## Alternatives and tradeoffs

- A streaming watermark and bounded queue would lower memory use but require explicit late-event and backpressure semantics. This offline batch path is simpler to reproduce.
- A fully virtual monotonic clock would avoid sleep; the optional paced mode demonstrates monotonic scheduling while the fast default keeps tests quick.
- Generic rule objects are auditable and configurable; their schema and feature vocabulary require strict validation. A learned model could capture interactions but would need independent data and calibration evidence.
- A standards-compliant JSON library would expand parser coverage; the bundled small parser keeps dependencies low but needs fuzz and conformance work.
- Dataset manifests and immutable development/holdout splits would strengthen reproducibility. Per-run input hashes alone do not supply that separation.

## Study route

Read `docs/ARCHITECTURE.md`, then trace `main` → `load_rules`/`load_events` → `normalize_events` → `pace_replay` → `evaluate` → `write_decisions`. Reconstruct one score from `reasons[]`; verify both hashes against the exact input bytes. Then run a task from `docs/DEBUGGING_EXERCISES.md` independently and defend your design with `docs/TECHNICAL_INTERVIEW.md`.

## Official references

- [C++ `std::chrono::steady_clock`](https://en.cppreference.com/w/cpp/chrono/steady_clock.html) and [C++ file streams](https://en.cppreference.com/w/cpp/io/basic_ifstream.html)
- [OpenSSL EVP digest API](https://docs.openssl.org/3.0/man3/EVP_DigestInit/)
- [Linux `timegm(3)`](https://man7.org/linux/man-pages/man3/timegm.3.html) and [`clock_gettime(2)`](https://man7.org/linux/man-pages/man2/clock_gettime.2.html)
- [RFC 8259 — JSON](https://www.rfc-editor.org/rfc/rfc8259), [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12)
- [Linux inotify documentation](https://docs.kernel.org/filesystems/inotify.html) and [`inotify(7)`](https://man7.org/linux/man-pages/man7/inotify.7.html) for possible upstream collectors; neither is implemented here.
