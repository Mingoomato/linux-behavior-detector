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
assert "bad labels CSV" in evaluate("quoted-label", 'entity_key,label\n"host,one",benign\n', [
    {"entity_key": "host,one", "decision": "benign"},
], False)

print("BHD metric validation: PASS")
