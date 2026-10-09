# Requirements traceability (SRS-02)

Code presence is not full requirement verification. The recorded test covers the generated 12-scenario fixture set only. See `docs/TEST_RESULTS.md`.

| Requirement | Source / artifact | Verification | Status |
|---|---|---|---|
| BHD-FR-001 | `src/bdetect.cpp:load_events`, `include/bdetect/json.hpp` | BHD-T-001 pending | IN_PROGRESS |
| BHD-FR-002 | host-level grouping; actor ignored | BHD-T-005 pending | IMPLEMENTED |
| BHD-FR-003 | fixed UTC buckets | BHD-T-002 pending | IN_PROGRESS |
| BHD-FR-004 | — | BHD-T-004 pending | NOT_STARTED |
| BHD-FR-005 | `evaluate` | BHD-T-003 pending | IN_PROGRESS |
| BHD-FR-006 | `evaluate` reason rules | BHD-T-008 pending | IN_PROGRESS |
| BHD-FR-007 | `load_rules` | BHD-T-011 pending | IN_PROGRESS |
| BHD-FR-008 | `evaluate` unknown/labels | BHD-T-009 pending | IMPLEMENTED |
| BHD-FR-009 | decision event IDs/reasons | BHD-T-008 pending | IMPLEMENTED |
| BHD-FR-010 | `write_decisions` | BHD-T-002 pending | IMPLEMENTED |
| BHD-FR-011 | `generate_fixtures` normal set | BHD-T-007 pending | IN_PROGRESS |
| BHD-FR-012 | `generate_fixtures` suspicious set | BHD-T-008 pending | IN_PROGRESS |
| BHD-FR-013 | `evaluate_labels` | tests/smoke.sh (synthetic fixture metrics) | IN_PROGRESS |
| BHD-FR-014 | — | BHD-T-013 pending | NOT_STARTED |
| BHD-FR-015 | record cap and event cap | BHD-T-010 pending | IN_PROGRESS |
| BHD-FR-016 | degraded coverage => unknown | BHD-T-009 pending | IMPLEMENTED |
| BHD-FR-017 | CLI dispatch | tests/smoke.sh (selected commands) | IN_PROGRESS |
| BHD-FR-018 | — | not implemented | NOT_STARTED |
| BHD-FR-019 | — | not implemented | NOT_STARTED |
| BHD-FR-020 | — | not applicable | NOT_APPLICABLE |
| BHD-NFR-01..06 | `docs/TEST_PLAN.md` | not run | NOT_STARTED |
