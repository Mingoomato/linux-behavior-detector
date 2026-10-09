# ADR-001: deterministic event-time windows and rules

- Status: initial lab baseline.
- Decision: normalize exact duplicate IDs and bounded out-of-order input, then score overlapping 10/30/60-second event-time windows per host. Preserve unknown attribution and use explainable counters.
- Reason: deterministic replay is more valuable than unvalidated process inference or an opaque model; sliding event-time windows avoid arbitrary UTC bucket boundaries.
- Consequence: this offline implementation holds the bounded corpus in memory and cannot identify missing events without producer sequence metadata. Late or conflicting evidence produces unknown rather than benign.
