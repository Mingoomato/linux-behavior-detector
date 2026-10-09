# Test results

Status: build and synthetic-fixture smoke test passed on the current Linux host.

- Release configure/build: passed with C++20.
- `ctest --test-dir build --output-on-failure`: 1/1 passed.
- Separate AddressSanitizer/UndefinedBehaviorSanitizer debug build and the same smoke test: passed.
- The smoke test generated and validated eight benign and four synthetic suspicious event streams, replayed all twelve, and evaluated the predictions: TP=4, FP=0, TN=8, FN=0, unknown=0.

These metrics are only a wiring check against labels generated alongside the fixtures. They are not an accuracy estimate or detection-quality result.

Not run: real ransomware or representative benign datasets, malformed-input fuzzing, boundary/late-event behavior, extended sanitizer cases, static analysis, or 100k-event performance measurement.
