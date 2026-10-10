#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys

binary = pathlib.Path(sys.argv[1])
work = pathlib.Path(sys.argv[2])

def evaluate(name, labels, predictions, expect_success):
    labels_path = work / f"{name}-labels.csv"
    predictions_path = work / f"{name}-predictions.ndjson"
    report_path = work / f"{name}-report.json"
    labels_path.write_text(labels, encoding="utf-8")
    predictions_path.write_text("".join(json.dumps(row) + "\n" for row in predictions), encoding="utf-8")
    result = subprocess.run([
        str(binary), "evaluate", "--pred", str(predictions_path),
        "--labels", str(labels_path), "--report", str(report_path),
    ], capture_output=True, text=True)
    if expect_success:
        assert result.returncode == 0, result.stderr
        return json.loads(report_path.read_text(encoding="utf-8"))
    assert result.returncode != 0, result.stdout
    return result.stderr

normal = evaluate("normal", "entity_key,label\nbenign-host,benign\npositive-host,suspicious\nunknown-host,suspicious\n", [
    {"entity_key": "benign-host", "decision": "benign"},
    {"entity_key": "positive-host", "decision": "suspicious"},
    {"entity_key": "unknown-host", "decision": "unknown"},
], True)
assert (normal["tp"], normal["fp"], normal["tn"], normal["fn"], normal["unknown"]) == (1, 0, 1, 0, 1)
assert (normal["precision_numerator"], normal["precision_denominator"]) == (1, 1)
assert (normal["recall_numerator"], normal["recall_denominator"]) == (1, 1)
assert (normal["fpr_numerator"], normal["fpr_denominator"]) == (0, 1)
assert (normal["fnr_numerator"], normal["fnr_denominator"]) == (0, 1)
assert normal["total_predictions"] == 3

quoted = evaluate("quoted-valid", (
    'entity_key,label\r\n"host,one",benign\r\n"host""two",suspicious\r\n'
    '"line\r\nbreak",benign\r\n'
), [
    {"entity_key": "host,one", "decision": "benign"},
    {"entity_key": 'host"two', "decision": "suspicious"},
    {"entity_key": "line\r\nbreak", "decision": "benign"},
], True)
assert (quoted["tp"], quoted["fp"], quoted["tn"], quoted["fn"]) == (1, 0, 2, 0)

zero_positive = evaluate("zero-positive", "entity_key,label\nonly-benign,benign\n", [
    {"entity_key": "only-benign", "decision": "benign"},
], True)
assert zero_positive["precision"] == "N/A" and zero_positive["precision_denominator"] == 0
assert zero_positive["recall"] == "N/A" and zero_positive["fnr"] == "N/A"
assert zero_positive["fpr"] == "0.000000"

# Decision records may exceed the 1 MiB event-input limit because they carry evidence IDs.
large_decision = {
    "decision_id": "large-decision", "entity_key": "large-host", "decision": "benign",
    "source_event_ids": [f"source-event-{index:06d}" for index in range(100_000)],
}
large_predictions = work / "large-predictions.ndjson"
large_predictions.write_text(json.dumps(large_decision) + "\n", encoding="utf-8")
large_labels = work / "large-labels.csv"
large_labels.write_text("entity_key,label\nlarge-host,benign\n", encoding="utf-8")
large_report = work / "large-report.json"
large_result = subprocess.run([
    str(binary), "evaluate", "--pred", str(large_predictions),
    "--labels", str(large_labels), "--report", str(large_report),
], capture_output=True, text=True)
assert large_result.returncode == 0, large_result.stderr
assert json.loads(large_report.read_text(encoding="utf-8"))["tn"] == 1
explained = subprocess.run([
    str(binary), "explain", "--decision-id", "large-decision", "--input", str(large_predictions),
], capture_output=True, text=True)
assert explained.returncode == 0 and len(explained.stdout) > 1024 * 1024

assert "invalid label row" in evaluate("invalid-label", "entity_key,label\nhost,maybe\n", [
    {"entity_key": "host", "decision": "benign"},
], False)
assert "missing label" in evaluate("missing-label", "entity_key,label\nother,benign\n", [
    {"entity_key": "host", "decision": "benign"},
], False)
assert "no prediction" in evaluate("extra-label", "entity_key,label\nhost,benign\nother,suspicious\n", [
    {"entity_key": "host", "decision": "benign"},
], False)
assert "duplicate entity label" in evaluate("duplicate-label", "entity_key,label\nhost,benign\nhost,suspicious\n", [
    {"entity_key": "host", "decision": "benign"},
], False)
assert "invalid prediction label" in evaluate("invalid-prediction", "entity_key,label\nhost,benign\n", [
    {"entity_key": "host", "decision": "maybe"},
], False)
assert "line 2" in evaluate("quote-after-close", 'entity_key,label\n"host"x,benign\n', [
    {"entity_key": "host", "decision": "benign"},
], False)
assert "quote inside unquoted field" in evaluate("quote-in-unquoted", 'entity_key,label\nhost"one,benign\n', [
    {"entity_key": "hostone", "decision": "benign"},
], False)
assert "unterminated quoted field" in evaluate("unterminated-quote", 'entity_key,label\n"host,benign', [
    {"entity_key": "host", "decision": "benign"},
], False)
assert "exactly two fields" in evaluate("extra-csv-column", "entity_key,label\nhost,benign,extra\n", [
    {"entity_key": "host", "decision": "benign"},
], False)
assert "duplicate entity label" in evaluate("duplicate-quoted-key",
    'entity_key,label\nhost,benign\n"host",suspicious\n', [
        {"entity_key": "host", "decision": "benign"},
    ], False)
assert "CSV field too large" in evaluate("oversized-csv-field",
    "entity_key,label\n\"" + "x" * (1024 * 1024) + "\",benign\n", [
        {"entity_key": "host", "decision": "benign"},
    ], False)

invalid_utf8_labels = work / "invalid-utf8-labels.csv"
invalid_utf8_labels.write_bytes(b"entity_key,label\nhost-\xff,benign\n")
invalid_utf8_predictions = work / "invalid-utf8-predictions.ndjson"
invalid_utf8_predictions.write_text(json.dumps({"entity_key": "host", "decision": "benign"}) + "\n",
                                    encoding="utf-8")
invalid_utf8_result = subprocess.run([
    str(binary), "evaluate", "--pred", str(invalid_utf8_predictions),
    "--labels", str(invalid_utf8_labels), "--report", str(work / "invalid-utf8-report.json"),
], capture_output=True, text=True)
assert invalid_utf8_result.returncode != 0 and "line 2" in invalid_utf8_result.stderr
assert "invalid UTF-8" in invalid_utf8_result.stderr

print("BHD metric validation: PASS")
