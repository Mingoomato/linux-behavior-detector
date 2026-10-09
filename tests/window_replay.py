#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys

binary = pathlib.Path(sys.argv[1])
baseline_path = pathlib.Path(sys.argv[2])
work = pathlib.Path(sys.argv[3])
rules = json.loads(baseline_path.read_text(encoding="utf-8"))
rules.update({
    "window_seconds": 10,
    "lateness_tolerance_ms": 2000,
    "min_event_count": 3,
    "rewrite_threshold": 2,
    "rename_threshold": 100,
    "delete_threshold": 100,
    "extension_types_threshold": 100,
})
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
        "actor": {"pid": None, "attribution": "unknown"},
        "evidence": {},
        "coverage": {"state": coverage},
    }

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
assert len(latest["source_event_ids"]) == 3, latest
assert int(latest["window_end"]) - int(latest["window_start"]) == 10, latest

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

invalid_rules = dict(rules, window_seconds=15)
invalid_path = work / "window-rules-invalid.json"
invalid_path.write_text(json.dumps(invalid_rules), encoding="utf-8")
invalid = subprocess.run([
    str(binary), "rules-validate", "--file", str(invalid_path),
], capture_output=True, text=True)
assert invalid.returncode != 0 and "10, 30, or 60" in invalid.stderr

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

print("BHD window/reorder/dedup smoke: PASS")
