# Requirements traceability (SRS-02)

Code presence is not full requirement verification. The recorded test covers the generated 12-scenario fixture set only. See `docs/TEST_RESULTS.md`.

| Requirement | Source / artifact | Verification | Status |
|---|---|---|---|
| BHD-FR-001 | `read_limited_line`, `valid_utf8`, `load_events`, `include/bdetect/json.hpp` | `tests/window_replay.py` covers line/field bounds and invalid UTF-8; full schema matrix pending | IN_PROGRESS |
| BHD-FR-002 | host-level grouping; actor ignored | BHD-T-005 pending | IMPLEMENTED |
| BHD-FR-003 | offline event-time replay | BHD-T-002 repeatability pending; no monotonic replay timer | IN_PROGRESS |
| BHD-FR-004 | `normalize_events` exact-ID dedupe, bounded lateness, stable reorder | `tests/window_replay.py`; producer sequence-gap detection unavailable | IN_PROGRESS |
| BHD-FR-005 | `evaluate` overlapping 10/30/60-second event-time windows | `tests/window_replay.py` covers 10-second edge | IMPLEMENTED |
| BHD-FR-006 | `evaluate` reason rules | BHD-T-008 pending | IN_PROGRESS |
| BHD-FR-007 | `load_rules` | BHD-T-011 pending | IN_PROGRESS |
| BHD-FR-008 | `evaluate` unknown/labels | BHD-T-009 pending | IMPLEMENTED |
| BHD-FR-009 | decision event IDs/reasons | per-rule numeric contribution output still pending | IN_PROGRESS |
| BHD-FR-010 | `write_decisions` | BHD-T-002 pending | IMPLEMENTED |
| BHD-FR-011 | `generate_fixtures` normal set | BHD-T-007 pending | IN_PROGRESS |
| BHD-FR-012 | `generate_fixtures` suspicious set | BHD-T-008 pending | IN_PROGRESS |
| BHD-FR-013 | `evaluate_labels` | tests/smoke.sh (synthetic fixture metrics) | IN_PROGRESS |
| BHD-FR-014 | — | BHD-T-013 pending | NOT_STARTED |
| BHD-FR-015 | bounded line reader, field caps, event cap, `max_entities` | targeted bound tests pass; bounded streaming queue/TTL and 100k stress pending | IN_PROGRESS |
| BHD-FR-016 | degraded coverage => unknown | BHD-T-009 pending | IMPLEMENTED |
| BHD-FR-017 | CLI dispatch | tests/smoke.sh (selected commands) | IN_PROGRESS |
| BHD-FR-018 | — | not implemented | NOT_STARTED |
| BHD-FR-019 | — | not implemented | NOT_STARTED |
| BHD-FR-020 | — | not applicable | NOT_APPLICABLE |
| BHD-NFR-01..06 | `docs/TEST_PLAN.md` | not run | NOT_STARTED |
