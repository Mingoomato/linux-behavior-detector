# Linux Ransomware Behavior Detection Lab

`bdetect` replays synthetic `event.v1` JSONL and applies deterministic, explainable rules to host-level windows. It never executes malware, modifies user files, blocks access, or claims process attribution. Every decision is marked `simulation_only`.

## Build and run

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
./build/bdetect rules-validate --file rules/baseline.json
./build/bdetect replay --input fixtures/sample.ndjson --rules rules/baseline.json --out decisions.ndjson
```

The implementation is self-contained C++20 and has no third-party runtime dependency.

## Capabilities and limits

The importer validates required event fields and reports line numbers for malformed input. Replay groups by `host_id` and fixed 30-second buckets, counts unique modified/renamed/deleted paths and extension diversity, and emits source event IDs and rule reasons. Missing or degraded coverage yields `unknown`. PID/actor data is not used for attribution.

The current implementation does not reorder late events, deduplicate input records before minimum-sample checks, load arbitrary per-rule operators/weights, implement a maximum-lateness buffer, or split development/holdout datasets automatically. Window boundaries use UTC epoch seconds and fixed buckets rather than a rolling window. Synthetic fixture generation writes only event records and refuses an existing output directory; it does not create file workloads.

Run `ctest --test-dir build --output-on-failure` to generate and replay eight benign and four synthetic suspicious scenarios. The smoke result is 4 true positives, 0 false positives, 8 true negatives, and 0 false negatives on those generated labels. These figures confirm fixture/rule wiring only; they are not a measured malware detection rate.

No detection-quality or performance results are claimed. This is a lab classifier, not a malware detector or endpoint protection product.
