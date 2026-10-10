#!/usr/bin/env python3
import json
import hashlib
import datetime
import pathlib
import subprocess
import sys

binary = pathlib.Path(sys.argv[1])
baseline_path = pathlib.Path(sys.argv[2])
work = pathlib.Path(sys.argv[3])
rules = json.loads(baseline_path.read_text(encoding="utf-8"))
rules.update({"window_seconds": 10, "lateness_tolerance_ms": 2000, "min_event_count": 3})
for rule in rules["rules"]:
    rule["min_sample_count"] = 3
    rule["threshold"] = 100
rewrite = next(rule for rule in rules["rules"] if rule["id"] == "R-MASS-REWRITE")
rewrite.update({"threshold": 2, "weight": 60})
rules_path = work / "window-rules.json"
rules_path.write_text(json.dumps(rules), encoding="utf-8")

def event(event_id, host, timestamp, path, kind="file.modified", coverage="healthy"):
    return {
        "schema_version": "event.v1",
        "event_id": event_id,
        "source": "window-test",
        "host_id": host,
        "observed_at": timestamp,
        "kind": kind,
        "severity": "info",
        "target": {"path": path},
        "actor": {"pid": None, "start_time_ticks": None, "attribution": "unknown"},
        "evidence": {},
        "coverage": {"state": coverage},
    }

payload_conflict = event("payload-conflict", "payload-conflict", "2026-10-09T12:00:05Z", "/lab/same.dat")
payload_conflict_changed = dict(payload_conflict, severity="high")
actor_untrusted = event("actor-untrusted", "actor-untrusted", "2026-10-09T12:00:05Z", "/lab/actor.dat")
actor_untrusted["actor"].update({"pid": 4242, "start_time_ticks": 91})

rows = [
    # The second event arrives two seconds behind the first, within tolerance.
    event("ordered-a", "ordered", "2026-10-09T12:00:05Z", "/lab/a.dat"),
    event("ordered-b", "ordered", "2026-10-09T12:00:03Z", "/lab/b.dat"),
    event("ordered-c", "ordered", "2026-10-09T12:00:05Z", "/lab/c.dat"),
    # Exact retransmission is deduplicated by event_id.
    event("ordered-c", "ordered", "2026-10-09T12:00:05Z", "/lab/c.dat"),
    event("window-old", "window", "2026-10-09T11:59:54Z", "/lab/old.dat"),
    event("window-new", "window", "2026-10-09T12:00:05Z", "/lab/new.dat"),
    event("late-first", "late", "2026-10-09T12:00:05Z", "/lab/first.dat"),
    event("late-drop", "late", "2026-10-09T12:00:02Z", "/lab/late.dat"),
    event("conflict-id", "conflict", "2026-10-09T12:00:05Z", "/lab/one.dat"),
    event("conflict-id", "conflict", "2026-10-09T12:00:05Z", "/lab/two.dat"),
    payload_conflict,
    payload_conflict_changed,
    actor_untrusted,
    event("degraded-1", "degraded", "2026-10-09T12:00:03Z", "/lab/d1.dat", coverage="degraded"),
    event("degraded-2", "degraded", "2026-10-09T12:00:04Z", "/lab/d2.dat", coverage="healthy"),
    event("degraded-3", "degraded", "2026-10-09T12:00:05Z", "/lab/d3.dat", coverage="healthy"),
    event("timestamp-utc", "timestamp-utc", "2026-10-09T12:00:05Z", "/lab/utc.dat"),
    event("timestamp-offset", "timestamp-offset", "2026-10-09T21:00:05.250+09:00", "/lab/offset.dat"),
    event("escaped\tid", "escaped\thost", "2026-10-09T12:00:05Z", "/lab/escaped.dat"),
    # Sequence order is independent from event-time ordering and input arrival.
    dict(event("seq-order-1", "seq-order", "2026-10-09T12:00:05Z", "/lab/s1.dat"),
         producer_session_id="boot-order", producer_sequence=1),
    dict(event("seq-order-3", "seq-order", "2026-10-09T12:00:06Z", "/lab/s3.dat"),
         producer_session_id="boot-order", producer_sequence=3),
    dict(event("seq-order-2", "seq-order", "2026-10-09T12:00:04Z", "/lab/s2.dat"),
         producer_session_id="boot-order", producer_sequence=2),
    dict(event("seq-gap-10", "seq-gap", "2026-10-09T12:00:03Z", "/lab/g10.dat"),
         producer_session_id="boot-gap", producer_sequence=10),
    dict(event("seq-gap-11", "seq-gap", "2026-10-09T12:00:04Z", "/lab/g11.dat"),
         producer_session_id="boot-gap", producer_sequence=11),
    dict(event("seq-gap-13", "seq-gap", "2026-10-09T12:00:05Z", "/lab/g13.dat"),
         producer_session_id="boot-gap", producer_sequence=13),
    dict(event("seq-restart-a", "seq-restart", "2026-10-09T12:00:03Z", "/lab/r1.dat"),
         producer_session_id="boot-old", producer_sequence=40),
    dict(event("seq-restart-b", "seq-restart", "2026-10-09T12:00:04Z", "/lab/r2.dat"),
         producer_session_id="boot-old", producer_sequence=41),
    dict(event("seq-restart-c", "seq-restart", "2026-10-09T12:00:05Z", "/lab/r3.dat"),
         producer_session_id="boot-new", producer_sequence=1),
    dict(event("seq-mixed-1", "seq-mixed", "2026-10-09T12:00:03Z", "/lab/m1.dat"),
         producer_session_id="boot-mixed", producer_sequence=1),
    event("seq-mixed-2", "seq-mixed", "2026-10-09T12:00:04Z", "/lab/m2.dat"),
    dict(event("seq-mixed-3", "seq-mixed", "2026-10-09T12:00:05Z", "/lab/m3.dat"),
         producer_session_id="boot-mixed", producer_sequence=2),
    dict(event("seq-conflict-a", "seq-conflict", "2026-10-09T12:00:03Z", "/lab/c1.dat"),
         producer_session_id="boot-conflict", producer_sequence=5),
    dict(event("seq-conflict-b", "seq-conflict", "2026-10-09T12:00:04Z", "/lab/c2.dat"),
         producer_session_id="boot-conflict", producer_sequence=5),
    dict(event("seq-conflict-c", "seq-conflict", "2026-10-09T12:00:05Z", "/lab/c3.dat"),
         producer_session_id="boot-conflict", producer_sequence=6),
]
input_path = work / "window-input.ndjson"
input_path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
output_path = work / "window-output.ndjson"
subprocess.run([
    str(binary), "replay", "--input", str(input_path),
    "--rules", str(rules_path), "--out", str(output_path),
], check=True, capture_output=True, text=True)
decisions = [json.loads(line) for line in output_path.read_text(encoding="utf-8").splitlines()]
by_host = {}
for decision in decisions:
    by_host.setdefault(decision["entity_key"], []).append(decision)

ordered = by_host["ordered"]
assert len(ordered) == 2, ordered
latest = ordered[-1]
assert latest["decision"] == "suspicious", latest
assert latest["simulation_only"] is True, latest
assert len(latest["source_event_ids"]) == 3, latest
assert int(latest["window_end"]) - int(latest["window_start"]) == 10, latest
reason = latest["reasons"][0]
assert reason == {
    "rule_id": "R-MASS-REWRITE", "feature": "unique_modified_files", "observed": 3,
    "operator": ">=", "threshold": 2, "weight": 60, "contribution": 60,
    "source_event_ids": ["ordered-a", "ordered-b", "ordered-c"],
}, reason
assert latest["ruleset_sha256"] == hashlib.sha256(rules_path.read_bytes()).hexdigest(), latest
assert latest["dataset_sha256"] == hashlib.sha256(input_path.read_bytes()).hexdigest(), latest

# Pacing uses a monotonic deadline but must not alter event-time decisions.
paced_out = work / "window-output-paced.ndjson"
subprocess.run([
    str(binary), "replay", "--input", str(input_path), "--rules", str(rules_path),
    "--out", str(paced_out), "--speed", "1000",
], check=True, capture_output=True, text=True)
assert paced_out.read_bytes() == output_path.read_bytes()

# A per-rule weight change is reflected in the score and in its explanation.
weighted_rules = json.loads(json.dumps(rules))
next(rule for rule in weighted_rules["rules"] if rule["id"] == "R-MASS-REWRITE")["weight"] = 17
weighted_rules["score_cutoff"] = 17
weighted_path = work / "window-rules-weighted.json"
weighted_path.write_text(json.dumps(weighted_rules), encoding="utf-8")
weighted_out = work / "window-output-weighted.ndjson"
subprocess.run([
    str(binary), "replay", "--input", str(input_path), "--rules", str(weighted_path),
    "--out", str(weighted_out),
], check=True, capture_output=True, text=True)
weighted_latest = [json.loads(line) for line in weighted_out.read_text(encoding="utf-8").splitlines()
                   if json.loads(line)["entity_key"] == "ordered"][-1]
assert weighted_latest["score"] == 17 and weighted_latest["reasons"][0]["contribution"] == 17

for operator, threshold in ((">=", 3), (">", 2), ("<=", 3), ("<", 4), ("==", 3)):
    operator_rules = json.loads(json.dumps(rules))
    operator_rules.update({"min_event_count": 3, "score_cutoff": 5})
    operator_rules["rules"] = [{
        "id": "T-OP", "feature": "event_count", "operator": operator,
        "threshold": threshold, "weight": 5, "min_sample_count": 3,
    }]
    operator_path = work / f"operator-{operator.replace('=', 'eq').replace('>', 'gt').replace('<', 'lt')}.json"
    operator_path.write_text(json.dumps(operator_rules), encoding="utf-8")
    operator_out = work / f"{operator_path.stem}.ndjson"
    subprocess.run([
        str(binary), "replay", "--input", str(input_path), "--rules", str(operator_path),
        "--out", str(operator_out),
    ], check=True, capture_output=True, text=True)
    operator_rows = [json.loads(line) for line in operator_out.read_text(encoding="utf-8").splitlines()]
    operator_latest = [row for row in operator_rows if row["entity_key"] == "ordered"][-1]
    assert operator_latest["score"] == 5 and operator_latest["reasons"][0]["operator"] == operator

sample_rules = json.loads(json.dumps(rules))
sample_rules.update({"min_event_count": 1, "score_cutoff": 5})
sample_rules["rules"] = [{
    "id": "T-SAMPLE", "feature": "event_count", "operator": ">=",
    "threshold": 0, "weight": 5, "min_sample_count": 4,
}]
sample_path = work / "sample-rules.json"
sample_path.write_text(json.dumps(sample_rules), encoding="utf-8")
sample_out = work / "sample-output.ndjson"
subprocess.run([
    str(binary), "replay", "--input", str(input_path), "--rules", str(sample_path),
    "--out", str(sample_out),
], check=True, capture_output=True, text=True)
sample_latest = [json.loads(line) for line in sample_out.read_text(encoding="utf-8").splitlines()
                 if json.loads(line)["entity_key"] == "ordered"][-1]
assert sample_latest["decision"] == "unknown"
assert "insufficient_sample_count:T-SAMPLE" in sample_latest["unknown_fields"]

window = by_host["window"][-1]
assert window["source_event_ids"] == ["window-new"], window
assert window["decision"] == "unknown" and "insufficient_events" in window["unknown_fields"], window

late = by_host["late"][-1]
assert late["decision"] == "unknown", late
assert late["coverage"] == "degraded", late
assert "late_event_beyond_tolerance" in late["unknown_fields"], late

conflict = by_host["conflict"][-1]
assert conflict["decision"] == "unknown", conflict
assert "conflicting_duplicate_event_id" in conflict["unknown_fields"], conflict
assert conflict["coverage"] == "degraded", conflict
payload_mismatch = by_host["payload-conflict"][-1]
assert payload_mismatch["decision"] == "unknown"
assert "conflicting_duplicate_event_id" in payload_mismatch["unknown_fields"]
assert "actor" not in by_host["actor-untrusted"][-1]
degraded = by_host["degraded"][-1]
assert degraded["decision"] == "unknown" and degraded["coverage"] == "degraded"
assert "coverage_degraded" in degraded["unknown_fields"]
assert by_host["timestamp-utc"][0]["window_end"] == by_host["timestamp-offset"][0]["window_end"]
assert by_host["escaped\thost"][0]["source_event_ids"] == ["escaped\tid"]

sequence_order = by_host["seq-order"][-1]
assert sequence_order["decision"] == "suspicious", sequence_order
assert "producer_sequence_gap" not in sequence_order["unknown_fields"], sequence_order
assert sequence_order["coverage"] == "observed", sequence_order
sequence_gap = by_host["seq-gap"][-1]
assert sequence_gap["decision"] == "unknown" and sequence_gap["coverage"] == "degraded", sequence_gap
assert "producer_sequence_gap" in sequence_gap["unknown_fields"], sequence_gap
sequence_restart = by_host["seq-restart"][-1]
assert "producer_sequence_gap" not in sequence_restart["unknown_fields"], sequence_restart
assert "producer_sequence_metadata_incomplete" not in sequence_restart["unknown_fields"], sequence_restart
sequence_mixed = by_host["seq-mixed"][-1]
assert sequence_mixed["decision"] == "unknown" and sequence_mixed["coverage"] == "degraded", sequence_mixed
assert "producer_sequence_metadata_incomplete" in sequence_mixed["unknown_fields"], sequence_mixed
sequence_conflict = by_host["seq-conflict"][-1]
assert "producer_sequence_conflict" in sequence_conflict["unknown_fields"], sequence_conflict
assert "producer_sequence_gap" not in sequence_conflict["unknown_fields"], sequence_conflict
assert not any("producer_sequence" in reason for reason in by_host["ordered"][-1]["unknown_fields"])

for duration in (10, 30, 60):
    candidate_rules = dict(rules, window_seconds=duration)
    candidate_path = work / f"window-rules-{duration}.json"
    candidate_path.write_text(json.dumps(candidate_rules), encoding="utf-8")
    candidate_out = work / f"window-output-{duration}.ndjson"
    subprocess.run([
        str(binary), "replay", "--input", str(input_path),
        "--rules", str(candidate_path), "--out", str(candidate_out),
    ], check=True, capture_output=True, text=True)
    candidate_rows = [json.loads(line) for line in candidate_out.read_text(encoding="utf-8").splitlines()]
    latest_ordered = [row for row in candidate_rows if row["entity_key"] == "ordered"][-1]
    assert int(latest_ordered["window_end"]) - int(latest_ordered["window_start"]) == duration

for duration in (30, 60):
    end = datetime.datetime(2026, 10, 9, 12, 1, 0, tzinfo=datetime.timezone.utc)
    to_timestamp = lambda value: value.strftime("%Y-%m-%dT%H:%M:%SZ")
    boundary_host = f"boundary-{duration}"
    boundary_rows = [
        event(f"{boundary_host}-before-left", boundary_host,
              to_timestamp(end - datetime.timedelta(seconds=duration + 1)), "/lab/before-left.dat"),
        event(f"{boundary_host}-left", boundary_host,
              to_timestamp(end - datetime.timedelta(seconds=duration)), "/lab/left.dat"),
        event(f"{boundary_host}-before-right", boundary_host,
              to_timestamp(end - datetime.timedelta(seconds=1)), "/lab/before-right.dat"),
        event(f"{boundary_host}-right", boundary_host, to_timestamp(end), "/lab/right.dat"),
    ]
    boundary_input = work / f"boundary-{duration}-input.ndjson"
    boundary_input.write_text("".join(json.dumps(row) + "\n" for row in boundary_rows), encoding="utf-8")
    boundary_rules = json.loads(json.dumps(rules))
    boundary_rules.update({"window_seconds": duration, "min_event_count": 3, "score_cutoff": 3})
    boundary_rules["rules"] = [{
        "id": "T-BOUNDARY", "feature": "event_count", "operator": ">=",
        "threshold": 3, "weight": 3, "min_sample_count": 3,
    }]
    boundary_rules_path = work / f"boundary-{duration}-rules.json"
    boundary_rules_path.write_text(json.dumps(boundary_rules), encoding="utf-8")
    boundary_output = work / f"boundary-{duration}-output.ndjson"
    subprocess.run([
        str(binary), "replay", "--input", str(boundary_input),
        "--rules", str(boundary_rules_path), "--out", str(boundary_output),
    ], check=True, capture_output=True, text=True)
    boundary_decisions = [json.loads(line) for line in boundary_output.read_text(encoding="utf-8").splitlines()]
    boundary_by_end = {int(row["window_end"]): row for row in boundary_decisions}
    right_epoch = int(end.timestamp())
    previous = boundary_by_end[right_epoch - 1]
    latest_boundary = boundary_by_end[right_epoch]
    assert set(previous["source_event_ids"]) == {
        f"{boundary_host}-before-left", f"{boundary_host}-left", f"{boundary_host}-before-right",
    }, previous
    assert set(latest_boundary["source_event_ids"]) == {
        f"{boundary_host}-left", f"{boundary_host}-before-right", f"{boundary_host}-right",
    }, latest_boundary
    assert previous["decision"] == "suspicious" and latest_boundary["decision"] == "suspicious"

invalid_rules = dict(rules, window_seconds=15)
invalid_path = work / "window-rules-invalid.json"
invalid_path.write_text(json.dumps(invalid_rules), encoding="utf-8")
invalid = subprocess.run([
    str(binary), "rules-validate", "--file", str(invalid_path),
], capture_output=True, text=True)
assert invalid.returncode != 0 and "10, 30, or 60" in invalid.stderr

invalid_operator_rules = json.loads(json.dumps(rules))
invalid_operator_rules["rules"][0]["operator"] = "!="
invalid_operator_path = work / "invalid-operator-rules.json"
invalid_operator_path.write_text(json.dumps(invalid_operator_rules), encoding="utf-8")
invalid_operator = subprocess.run([
    str(binary), "rules-validate", "--file", str(invalid_operator_path),
], capture_output=True, text=True)
assert invalid_operator.returncode != 0 and "unsupported rule operator" in invalid_operator.stderr

missing_rule_field_rules = json.loads(json.dumps(rules))
del missing_rule_field_rules["rules"][0]["min_sample_count"]
missing_rule_field_path = work / "missing-rule-field.json"
missing_rule_field_path.write_text(json.dumps(missing_rule_field_rules), encoding="utf-8")
missing_rule_field = subprocess.run([
    str(binary), "rules-validate", "--file", str(missing_rule_field_path),
], capture_output=True, text=True)
assert missing_rule_field.returncode != 0 and "min_sample_count" in missing_rule_field.stderr

limited_rules = dict(rules, max_entities=1)
limited_path = work / "window-rules-limited.json"
limited_path.write_text(json.dumps(limited_rules), encoding="utf-8")
limited = subprocess.run([
    str(binary), "replay", "--input", str(input_path),
    "--rules", str(limited_path), "--out", str(work / "window-output-limited.ndjson"),
], capture_output=True, text=True)
assert limited.returncode != 0 and "entity cardinality limit" in limited.stderr

oversized_path = work / "oversized-record.ndjson"
oversized_path.write_text(" " * (1024 * 1024 + 1) + "\n", encoding="utf-8")
oversized = subprocess.run([
    str(binary), "validate-events", "--input", str(oversized_path),
], capture_output=True, text=True)
assert oversized.returncode != 0 and "line 1" in oversized.stderr and "record too large" in oversized.stderr

long_path_input = work / "long-path.ndjson"
long_path_input.write_text(json.dumps(event(
    "long-path", "long-path", "2026-10-09T12:00:05Z", "/" + "x" * 4096,
)) + "\n", encoding="utf-8")
long_path = subprocess.run([
    str(binary), "validate-events", "--input", str(long_path_input),
], capture_output=True, text=True)
assert long_path.returncode != 0 and "event field length limit" in long_path.stderr

missing_event_field_path = work / "missing-event-field.ndjson"
missing_event = event("missing-field", "missing-field", "2026-10-09T12:00:05Z", "/lab/missing.dat")
del missing_event["source"]
missing_event_field_path.write_text(json.dumps(missing_event) + "\n", encoding="utf-8")
missing_event_field = subprocess.run([
    str(binary), "validate-events", "--input", str(missing_event_field_path),
], capture_output=True, text=True)
assert missing_event_field.returncode != 0 and "line 1" in missing_event_field.stderr

sequence_pair_path = work / "incomplete-producer-sequence.ndjson"
sequence_pair = event("sequence-pair", "sequence-pair", "2026-10-09T12:00:05Z", "/lab/sequence.dat")
sequence_pair["producer_session_id"] = "boot-pair"
sequence_pair_path.write_text(json.dumps(sequence_pair) + "\n", encoding="utf-8")
sequence_pair_result = subprocess.run([
    str(binary), "validate-events", "--input", str(sequence_pair_path),
], capture_output=True, text=True)
assert sequence_pair_result.returncode != 0 and "must appear together" in sequence_pair_result.stderr

for invalid_sequence in (0, 1.5, 9007199254740992):
    bad_sequence = event(f"bad-sequence-{invalid_sequence}", "bad-sequence",
                         "2026-10-09T12:00:05Z", "/lab/sequence.dat")
    bad_sequence.update({"producer_session_id": "boot-bad", "producer_sequence": invalid_sequence})
    bad_sequence_path = work / f"bad-sequence-{invalid_sequence}.ndjson"
    bad_sequence_path.write_text(json.dumps(bad_sequence) + "\n", encoding="utf-8")
    bad_sequence_result = subprocess.run([
        str(binary), "validate-events", "--input", str(bad_sequence_path),
    ], capture_output=True, text=True)
    assert bad_sequence_result.returncode != 0 and "producer_sequence" in bad_sequence_result.stderr

numeric_event = event("numeric", "numeric", "2026-10-09T12:00:05Z", "/lab/numeric.dat")
numeric_event["target"]["device"] = 1
valid_numeric_line = json.dumps(numeric_event)
for invalid_number in ("+1", "01", "1.", "NaN", "Infinity"):
    bad_number_line = valid_numeric_line.replace('"device": 1', f'"device": {invalid_number}')
    assert bad_number_line != valid_numeric_line
    bad_number_path = work / f"bad-number-{invalid_number.replace('+', 'plus')}.ndjson"
    bad_number_path.write_text(bad_number_line + "\n", encoding="utf-8")
    bad_number = subprocess.run([
        str(binary), "validate-events", "--input", str(bad_number_path),
    ], capture_output=True, text=True)
    assert bad_number.returncode != 0 and "line 1" in bad_number.stderr

duplicate_key_line = valid_numeric_line.replace('"device": 1', '"device": 1, "device": 2')
duplicate_key_path = work / "duplicate-json-key.ndjson"
duplicate_key_path.write_text(duplicate_key_line + "\n", encoding="utf-8")
duplicate_key = subprocess.run([
    str(binary), "validate-events", "--input", str(duplicate_key_path),
], capture_output=True, text=True)
assert duplicate_key.returncode != 0 and "duplicate object key" in duplicate_key.stderr

unicode_path = work / "unicode-surrogate-pair.ndjson"
unicode_row = event("emoji-😀", "emoji-host", "2026-10-09T12:00:05Z", "/lab/😀.dat")
unicode_path.write_text(json.dumps(unicode_row, ensure_ascii=True) + "\n", encoding="utf-8")
unicode_result = subprocess.run([
    str(binary), "validate-events", "--input", str(unicode_path),
], capture_output=True, text=True)
assert unicode_result.returncode == 0, unicode_result.stderr

unpaired_path = work / "unicode-unpaired-surrogate.ndjson"
unpaired_text = json.dumps(event(
    "unpaired", "unpaired", "2026-10-09T12:00:05Z", "/lab/surrogate.dat",
), ensure_ascii=True).replace("/lab/surrogate.dat", "/lab/\\ud800.dat")
unpaired_path.write_text(unpaired_text + "\n", encoding="utf-8")
unpaired_result = subprocess.run([
    str(binary), "validate-events", "--input", str(unpaired_path),
], capture_output=True, text=True)
assert unpaired_result.returncode != 0 and "surrogate" in unpaired_result.stderr

invalid_utf8_path = work / "invalid-utf8.ndjson"
invalid_utf8_path.write_bytes(
    b'{"schema_version":"event.v1","event_id":"utf8","host_id":"utf8",'
    b'"observed_at":"2026-10-09T12:00:05Z","kind":"file.modified",'
    b'"target":{"path":"/bad-\xff"},"coverage":{"state":"healthy"}}\n'
)
invalid_utf8 = subprocess.run([
    str(binary), "validate-events", "--input", str(invalid_utf8_path),
], capture_output=True, text=True)
assert invalid_utf8.returncode != 0 and "line 1" in invalid_utf8.stderr and "invalid UTF-8" in invalid_utf8.stderr

invalid_timestamp_path = work / "invalid-timestamp.ndjson"
invalid_timestamp_path.write_text(json.dumps(event(
    "invalid-date", "invalid-date", "2026-02-30T12:00:05Z", "/lab/invalid.dat",
)) + "\n", encoding="utf-8")
invalid_timestamp = subprocess.run([
    str(binary), "validate-events", "--input", str(invalid_timestamp_path),
], capture_output=True, text=True)
assert invalid_timestamp.returncode != 0 and "line 1" in invalid_timestamp.stderr

missing_timezone_path = work / "missing-timezone.ndjson"
missing_timezone_path.write_text(json.dumps(event(
    "missing-zone", "missing-zone", "2026-10-09T12:00:05", "/lab/no-zone.dat",
)) + "\n", encoding="utf-8")
missing_timezone = subprocess.run([
    str(binary), "validate-events", "--input", str(missing_timezone_path),
], capture_output=True, text=True)
assert missing_timezone.returncode != 0 and "observed_at" in missing_timezone.stderr

leap_path = work / "valid-leap-day.ndjson"
leap_path.write_text(json.dumps(event(
    "valid-leap", "valid-leap", "2024-02-29T12:00:05Z", "/lab/leap.dat",
)) + "\n", encoding="utf-8")
valid_leap = subprocess.run([
    str(binary), "validate-events", "--input", str(leap_path),
], capture_output=True, text=True)
assert valid_leap.returncode == 0 and '"records":1' in valid_leap.stdout

long_span_path = work / "long-span.ndjson"
long_span_path.write_text("".join(json.dumps(row) + "\n" for row in [
    event("span-old", "span", "2024-02-29T12:00:05Z", "/lab/old.dat"),
    event("span-new", "span", "2026-10-09T12:00:05Z", "/lab/new.dat"),
]), encoding="utf-8")
long_span = subprocess.run([
    str(binary), "replay", "--input", str(long_span_path), "--rules", str(rules_path),
    "--out", str(work / "long-span-output.ndjson"), "--speed", "1",
], capture_output=True, text=True)
assert long_span.returncode != 0 and "exceeds one hour" in long_span.stderr

print("BHD window/reorder/dedup smoke: PASS")
