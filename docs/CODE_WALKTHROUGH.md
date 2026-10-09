# Code Walkthrough — Linux Ransomware Behavior Detection Lab

## 1. CLI dispatch

`main` in `src/bdetect.cpp` reads `argv[1]` and dispatches each operation. `replay` imports events and rules before writing decisions; `evaluate` reads predictions and labels; `generate-fixtures` is restricted to a newly created output directory beneath a preexisting sandbox. Exceptions are caught at the top and return status 2.

## 2. Event parsing

`load_events` uses `read_limited_line` to read at most 1 MiB per record before adding another byte, then `valid_utf8` rejects malformed UTF-8 before parsing. `bdetect::json::Parser` in `include/bdetect/json.hpp` builds a value tree from owned `std::string`, `std::map`, and `std::vector` values. It rejects duplicate object keys, control bytes, invalid escapes, unsupported Unicode surrogate escapes, nesting beyond 32, and JSON text larger than 1 MiB. The importer also applies explicit length limits to event IDs, host IDs, kinds, and paths.

`required` enforces presence; `string_or` extracts expected strings. `parse_time` converts an ISO-like timestamp to epoch seconds through `timegm`. The importer retains event ID, host ID, kind, path, timestamp, and coverage. Any exception gains line context.

## 3. Rules and aggregation

`load_rules` requires `schema_version=rules.v1`, reads window size, lateness tolerance, host bound, minimum sample count, thresholds, and score cutoff, then validates integer ranges and limits the window to 10, 30, or 60 seconds. `normalize_events` removes exact duplicate IDs, marks conflicting IDs, drops per-host events that arrive later than the configured tolerance, checks host cardinality, and sorts the accepted copy by host, event time, then ID.

`evaluate` visits each distinct event timestamp for a host as a window endpoint. A moving left index skips events older than `endpoint - window_seconds`; the remaining range is the current sliding window. Sets count unique modified/renamed/deleted paths, extensions, and source event IDs. Unknown/degraded coverage, conflicting IDs, late events, or insufficient sample count yields `unknown`; otherwise threshold checks add the current named contributions and the score cutoff selects benign or suspicious.

This is intentionally easy to inspect, not a general rule DSL. Replay is offline rather than paced by a monotonic clock; out-of-tolerance events are excluded and lower that host's decisions to unknown. Missing records cannot be detected without source sequence metadata. Some configured weights remain unused.

## 4. Output and metrics

`write_decisions` serializes the window, score, classification, rules revision, coverage, event IDs, reason IDs, and unknown fields. `simulation_only` is always true. The local escaping helper handles common JSON escapes but is not a full canonical serializer.

`evaluate_labels` maps each `entity_key` to a CSV label, counts TP/FP/TN/FN/unknown, and emits precision/recall/FPR/FNR with `N/A` for a zero denominator. `explain` scans serialized decisions for the requested ID. The metric report does not yet include every denominator or robust multi-column CSV handling.

## 5. Synthetic fixture generation

`generate_fixtures` resolves the sandbox, creates a new output directory with restrictive mode, checks that it is beneath the sandbox, then writes eight benign and four synthetic suspicious event streams plus `labels.csv`. It emits metadata only and never creates or alters workload files. The smoke test validates, replays, concatenates, and evaluates these outputs.

## 6. Memory and resource review

`load_events` stores the entire corpus in memory; normalization creates a second owning vector. `evaluate` uses non-owning `Event*` pointers into that stable normalized vector and copies unique path strings into per-window sets. Streams are RAII-managed. There are no worker threads; bounded streaming backpressure is not implemented.
