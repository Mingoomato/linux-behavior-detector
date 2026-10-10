#!/bin/sh
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
bin_dir=${BIN_DIR:-"$root_dir/build"}
bin="$bin_dir/bdetect"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir "$tmp/sandbox"
"$bin" rules-validate --file "$root_dir/rules/baseline.json"
"$bin" generate-fixtures --root "$tmp/sandbox" --out "$tmp/sandbox/fixtures"
: >"$tmp/predictions.ndjson"
for input in "$tmp"/sandbox/fixtures/*.ndjson; do
    scenario=$(basename "$input" .ndjson)
    "$bin" validate-events --input "$input"
    "$bin" replay --input "$input" --rules "$root_dir/rules/baseline.json" --out "$tmp/one.ndjson"
    "$bin" explain --decision-id "decision-1-$scenario" --input "$tmp/one.ndjson" >/dev/null
    cat "$tmp/one.ndjson" >>"$tmp/predictions.ndjson"
done
"$bin" evaluate --pred "$tmp/predictions.ndjson" \
    --labels "$tmp/sandbox/fixtures/labels.csv" --report "$tmp/report.json"
python3 - "$tmp/report.json" "$tmp/predictions.ndjson" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    result = json.load(f)
assert (result["tp"], result["fp"], result["tn"], result["fn"], result["unknown"]) == (4, 0, 8, 0, 0), result
with open(sys.argv[2], encoding="utf-8") as f:
    decisions = [json.loads(line) for line in f if line.strip()]
assert all(row["simulation_only"] is True for row in decisions)
suspicious = [row for row in decisions if row["decision"] == "suspicious"]
assert len(suspicious) == 4
for row in suspicious:
    assert row["reasons"] and row["source_event_ids"]
    for reason in row["reasons"]:
        assert reason["source_event_ids"]
        assert set(reason["source_event_ids"]).issubset(row["source_event_ids"])
PY

python3 "$root_dir/tests/window_replay.py" "$bin" \
    "$root_dir/rules/baseline.json" "$tmp"
python3 "$root_dir/tests/metrics.py" "$bin" "$tmp"

echo "BHD synthetic fixture smoke: PASS"
