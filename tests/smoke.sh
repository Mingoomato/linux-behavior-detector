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
    "$bin" validate-events --input "$input"
    "$bin" replay --input "$input" --rules "$root_dir/rules/baseline.json" --out "$tmp/one.ndjson"
    cat "$tmp/one.ndjson" >>"$tmp/predictions.ndjson"
done
"$bin" evaluate --pred "$tmp/predictions.ndjson" \
    --labels "$tmp/sandbox/fixtures/labels.csv" --report "$tmp/report.json"
python3 - "$tmp/report.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    result = json.load(f)
assert (result["tp"], result["fp"], result["tn"], result["fn"], result["unknown"]) == (4, 0, 8, 0, 0), result
PY

echo "BHD synthetic fixture smoke: PASS"
