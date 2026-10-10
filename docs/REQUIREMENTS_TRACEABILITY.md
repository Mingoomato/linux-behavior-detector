# Requirements traceability (SRS-02)

Code presence is not full requirement verification. CTest covers generated fixtures plus focused contract, rule, replay, and metric cases. See `docs/TEST_RESULTS.md` for remaining SRS gates.

| Requirement | Source / artifact | Verification | Status |
|---|---|---|---|
| BHD-FR-001 | `contracts/event-v1.schema.json`, `read_limited_line`, `valid_utf8`, `load_events`, `parse_time` | Generated events pass Draft 2020-12 schema validation; focused required-field/type/timestamp/size, duplicate-key, strict-number and Unicode tests pass; optional Clang JSON parser fuzzer completed one 100k ASan/UBSan campaign; importer/timestamp fuzz and negative schema matrix remain open | IN_PROGRESS |
| BHD-FR-002 | host-level grouping; actor ignored | `tests/window_replay.py` supplies an untrusted PID with unknown attribution and asserts no actor is emitted | IMPLEMENTED |
| BHD-FR-003 | `pace_replay`, `std::chrono::steady_clock`, event-time windows | `tests/window_replay.py` checks paced/unpaced byte-equivalence; this remains an offline batch replayer | IMPLEMENTED |
| BHD-FR-004 | `normalize_events` exact-ID dedupe, bounded lateness, stable reorder, optional producer session/sequence validation | `tests/window_replay.py` covers in-tolerance event-time reorder, numeric sequence ordering, a gap, producer restart, sequence collision, mixed metadata, and missing-pair rejection; whole-corpus batch finalization only | IMPLEMENTED_BATCH_SCOPE |
| BHD-FR-005 | `evaluate` overlapping 10/30/60-second event-time windows | `tests/window_replay.py` checks exact left-edge inclusion, one-second-outside exclusion, right-edge inclusion, and left-index advancement for 10/30/60-second windows | IMPLEMENTED |
| BHD-FR-006 | configured rules in `rules/baseline.json`, `evaluate` | generated rewrite/rename/delete/mixed fixtures; configurable explainable scoring | IN_PROGRESS |
| BHD-FR-007 | `Rule`, `load_rules` | `tests/window_replay.py` checks all five operators, configured weights/thresholds, per-rule samples, and invalid operator/window | IMPLEMENTED |
| BHD-FR-008 | `evaluate` unknown/labels | BHD-T-009 pending | IMPLEMENTED |
| BHD-FR-009 | `Decision`, `Reason`, `write_decisions` | structured contributions map each matching rule to feature-specific source IDs; output includes window IDs, unknown fields, time window, and hashes | IMPLEMENTED |
| BHD-FR-010 | `write_decisions` | `simulation_only=true` asserted for generated replay output | IMPLEMENTED |
| BHD-FR-011 | `generate_fixtures` normal scenarios | CTest generates eight differentiated benign synthetic scenarios and evaluates labels; these are pipeline fixtures only | IMPLEMENTED |
| BHD-FR-012 | `generate_fixtures` suspicious scenarios | `tests/smoke.sh` asserts all four synthetic suspicious cases and their contributing event IDs; these are still synthetic-only | IMPLEMENTED |
| BHD-FR-013 | `evaluate_labels` | `tests/metrics.py` checks TP/FP/TN/FN/unknown, rate numerators/denominators, N/A, invalid labels, entity mismatches, bounded quoted commas/quotes/newlines, malformed quoting, and duplicate decoded keys | IMPLEMENTED |
| BHD-FR-014 | `dataset-freeze`, `dataset-audit`, `bdetect.dataset_freeze.v1`, `bdetect.dataset_audit.v1` | Separate dev/holdout files and exact ruleset hash can be frozen in a new read-only manifest; each audit appends hash/size match status to an owner-only locked ledger before returning. Code and schemas are unverified; split independence and trustworthy external ledger protection remain operator responsibilities. | IMPLEMENTED_UNVERIFIED |
| BHD-FR-015 | bounded line reader, `MAX_INPUT_FILE_BYTES`, `release_event_payload`, field/event/prediction caps, `max_entities`, `MAX_RULE_PAIR_UPDATES` | Code caps input files at 512 MiB, event records at 1 MiB, decision records at 64 MiB, event/prediction cardinality at 1,000,000, and rule-analysis pair updates at 10,000,000. Batch scoring releases string payloads after the active window passes them. These changes are unverified; bounded online queue, backpressure, and watermark/interval TTL eviction remain absent. | PARTIAL_UNVERIFIED |
| BHD-FR-016 | degraded coverage => unknown | BHD-T-009 pending | IMPLEMENTED |
| BHD-FR-017 | CLI dispatch | `tests/smoke.sh` covers `replay`, `evaluate`, `explain`, `rules-validate`, and `generate-fixtures` | IMPLEMENTED |
| BHD-FR-018 | `evaluate_labels`, `PredictionRecord`, `write_csv_cell`, `html_escape`, `--csv-report`, `--html-report` | Optional CSV metrics/timeline and escaped static HTML confusion/timeline are implemented; rows omit raw paths and are capped at 100,000, predictions at 1,000,000. Report-specific verification has not been run. | IMPLEMENTED_UNVERIFIED |
| BHD-FR-019 | `analyze_rule_correlations`, `analyze-rules`, `contracts/rule-analysis-v1.schema.json` | Reports bounded per-decision pair contingency counts, Jaccard similarity, and phi correlation; it does not change rule weights. Implementation and schema have not been technically verified. | IMPLEMENTED_UNVERIFIED |
| BHD-FR-020 | — | not applicable | NOT_APPLICABLE |
| BHD-NFR-01 | deterministic replay | `tests/window_replay.py` compares paced/unpaced output bytes | PASS_SELECTED_CASES |
| BHD-NFR-02 | measurable evidence | synthetic confusion matrix, event IDs, and 100k wall-time/RSS/p95 stats recorded; repeated baseline and representative data remain pending | PARTIAL |
| BHD-NFR-03 | 100k performance | one 100k multi-window run reports wall time, peak RSS, and 100k per-decision latency samples in `docs/TEST_RESULTS.md`; no repeated baseline | PARTIAL |
| BHD-NFR-04 | malformed input stability | required fields, UTF-8, timestamp, rule errors plus Release/ASan/UBSan; optional parser fuzzer completed 100k runs without crash, broader importer/timestamp fuzzing remains open | PARTIAL |
| BHD-NFR-05 | synthetic expectation | 4/4 generated suspicious fixtures and 0/8 benign false positives in the generated wiring check only | PASS_SYNTHETIC_ONLY |
| BHD-NFR-06 | explainability | every suspicious fixture includes rule-specific contributing event IDs; focused test asserts mapping | PASS_SELECTED_CASES |
