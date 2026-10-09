# ADR-001: deterministic fixed-window rules

- Status: initial lab baseline.
- Decision: group by host and fixed UTC buckets; preserve unknown attribution and use explainable counters.
- Reason: deterministic replay is more valuable than unvalidated process inference or an opaque model.
- Consequence: a burst crossing a bucket edge can split, and event reordering/deduplication remains future work.
