# Architecture

The executable has four boundaries: bounded JSON parsing, event schema extraction, deterministic host/window aggregation, and JSONL decision output. Rules are versioned JSON and validated before replay. The parser limits records to 1 MiB, the importer caps the corpus at one million events, and the rule set bounds host cardinality. Events with unknown actors remain host-level evidence.

Before scoring, replay removes exact duplicate event IDs, marks conflicting IDs as degraded, drops events arriving later than the configured tolerance, and stably orders accepted events by host and event time. Each distinct event second becomes a decision endpoint; a configured 10/30/60-second interval ending there forms an overlapping event-time sliding window. The engine counts unique modified, renamed, deleted, and extension values. Insufficient samples or degraded evidence produce `unknown`. Evaluation joins decisions to a scenario-label CSV and reports TP/FP/TN/FN plus precision/recall/FPR/FNR with `N/A` for zero denominators.

This release intentionally has no model training, file blocking, process inference, or online collection.
