#!/usr/bin/env python3
"""Real CLI checks for watermark ordering, rejection and bounded-queue coverage."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

binary, baseline = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()

def event(number, second):
    return {"schema_version": "event.v1", "event_id": f"event-{number}",
            "source": "stream-test", "host_id": "lab", "observed_at": f"2026-10-10T00:00:{second:02d}Z",
            "kind": "file.modified", "severity": "info", "target": {"path": f"/lab/file-{number}"},
            "actor": {"attribution": "unknown", "pid": None, "start_time_ticks": None},
            "coverage": {"state": "healthy"}, "evidence": {}}

with tempfile.TemporaryDirectory(prefix="bdetect-stream-") as tmp:
    root = Path(tmp)
    rules = json.loads(baseline.read_text())
    rules["lateness_tolerance_ms"] = 2000
    rulefile = root / "rules.json"
    rulefile.write_text(json.dumps(rules))
    source, target = root / "events.ndjson", root / "decisions.ndjson"

    def replay(rows, stream=True, success=True):
        source.write_text("".join(json.dumps(row) + "\n" for row in rows))
        args = [str(binary), "replay", "--input", str(source), "--rules", str(rulefile), "--out", str(target)]
        if stream:
            args.append("--stream")
        result = subprocess.run(args, text=True, capture_output=True, timeout=20)
        assert (result.returncode == 0) == success, (result.stdout, result.stderr)
        return [json.loads(line) for line in target.read_text().splitlines()] if success else result

    ordered = [event(1, 10), event(2, 11), event(3, 12), event(4, 14)]
    expected = replay(ordered)
    actual = replay([ordered[2], ordered[0], ordered[1], ordered[1], ordered[3]])
    def semantic(rows):
        return [{k: v for k, v in row.items() if k not in ("dataset_sha256", "decision_id")} for row in rows]
    assert semantic(actual) == semantic(expected), (actual, expected)
    target.write_text("preserved destination\n")
    replay([event(1, 10), event(2, 14), event(3, 11)], success=False)
    assert target.read_text() == "preserved destination\n"
    assert not list(root.glob("*.tmp*")), list(root.iterdir())
    overflow = replay([event(n, 10) for n in range(4097)])
    assert len(overflow) == 1 and overflow[0]["decision"] == "unknown"
    assert "bounded_reorder_queue_overflow" in json.dumps(overflow[0])
print("stream watermark, late rejection and overflow coverage: PASS")
