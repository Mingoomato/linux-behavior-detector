# Code Walkthrough — Linux Ransomware Behavior Detection Lab

## 1. CLI dispatch

`main` in `src/bdetect.cpp` reads `argv[1]` and dispatches each operation. `replay` imports events and rules before writing decisions; `evaluate` reads predictions and labels; `generate-fixtures` is restricted to a newly created output directory beneath a preexisting sandbox. Exceptions are caught at the top and return status 2.

## 2. Event parsing

`load_events` reads one line at a time. `bdetect::json::Parser` in `include/bdetect/json.hpp` builds a value tree from owned `std::string`, `std::map`, and `std::vector` values. It rejects duplicate object keys, control bytes, invalid escapes, unsupported Unicode surrogate escapes, nesting beyond 32, and JSON text larger than 1 MiB.

`required` enforces presence; `string_or` extracts expected strings. `parse_time` converts an ISO-like timestamp to epoch seconds through `timegm`. The importer retains event ID, host ID, kind, path, timestamp, and coverage. Any exception gains line context.

## 3. Rules and aggregation

`load_rules` requires `schema_version=rules.v1`, reads window size, minimum sample count, thresholds, and score cutoff, then rejects selected out-of-range values. `evaluate` floors the event epoch to a fixed window bucket and groups event pointers by `(host, start)`.

For each group, sets count unique modified/renamed/deleted paths, extensions, and source event IDs. Degraded or unsupported coverage yields `unknown`; low sample count also yields `unknown`. Otherwise threshold checks add fixed rule contributions and the score cutoff selects benign or suspicious.

This is intentionally easy to inspect, not a general rule DSL. Some configured weights and lateness settings are not fully used, duplicates can contribute to the sample count, and windows are fixed buckets rather than rolling windows.

## 4. Output and metrics

`write_decisions` serializes the window, score, classification, rules revision, coverage, event IDs, reason IDs, and unknown fields. `simulation_only` is always true. The local escaping helper handles common JSON escapes but is not a full canonical serializer.

`evaluate_labels` maps each `entity_key` to a CSV label, counts TP/FP/TN/FN/unknown, and emits precision/recall/FPR/FNR with `N/A` for a zero denominator. `explain` scans serialized decisions for the requested ID. The metric report does not yet include every denominator or robust multi-column CSV handling.

## 5. Synthetic fixture generation

`generate_fixtures` resolves the sandbox, creates a new output directory with restrictive mode, checks that it is beneath the sandbox, then writes eight benign and four synthetic suspicious event streams plus `labels.csv`. It emits metadata only and never creates or alters workload files. The smoke test validates, replays, concatenates, and evaluates these outputs.

## 6. Memory and resource review

`load_events` stores the entire corpus in memory. `evaluate` adds maps of non-owning `Event*` pointers and copies unique path strings into sets. Pointer lifetimes are safe only because the source vector remains alive and unchanged. Streams are RAII-managed. There are no worker threads; bounded streaming backpressure is not implemented.
