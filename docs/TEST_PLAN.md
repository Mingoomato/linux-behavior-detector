# Test plan

- Verify JSON line size, schema, duplicate keys, malformed Unicode escapes, invalid timestamps, missing fields, and line-number diagnostics.
- Replay identical fixture sets twice and compare normalized decisions.
- Test exact bucket edges, out-of-order and duplicate events, actor unknown state, insufficient samples, and degraded coverage.
- Generate all 8 benign and 4 suspicious synthetic scenarios inside a new sandbox directory; calculate confusion metrics and preserve labels.
- Test negative rule values, malformed rules, empty metric denominators, and output errors.
- Measure 100k records, peak RSS, and runtime only on a documented machine.

The synthetic fixture smoke test has been run. Boundary, malformed-input, fuzz, sanitizer, static-analysis, and performance scenarios remain pending.
