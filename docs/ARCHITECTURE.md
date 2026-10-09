# Architecture

The executable has four boundaries: bounded JSON parsing, event schema extraction, deterministic host/window aggregation, and JSONL decision output. Rules are versioned JSON and validated before replay. Input is capped at 1 MiB per record and one million events. Events with unknown actors remain host-level evidence.

The engine uses fixed UTC buckets for deterministic replay. Rule contributions currently cover mass rewrite, rename, deletion, and extension diversity. An unknown decision is preferred when sample count is insufficient or coverage is degraded. Evaluation joins decisions to a scenario-label CSV and reports TP/FP/TN/FN plus precision/recall/FPR/FNR with `N/A` for zero denominators.

This release intentionally has no model training, file blocking, process inference, or online collection.
