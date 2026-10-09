# Threat model

## Inputs

NDJSON, rules JSON, labels CSV, and fixture output paths are untrusted. JSON nesting and record size are bounded. Duplicate JSON object keys, malformed strings, missing fields, invalid timestamps, and out-of-range rule limits are rejected.

## Privacy and attribution

Only event metadata is consumed. The engine does not read file contents or environment variables. Input paths may be personal data; the current output includes host identifiers and event IDs, so all artifacts should remain local unless reviewed. No process identity is inferred from timestamps or inotify events.

## Residual risks

The custom JSON parser rejects UTF-16 surrogate escapes and accepts numeric syntax through the C library parser; extensive standards conformance and fuzzing have not been established. Rules and fixtures are not a representative malware dataset. Fixed windows can split bursts at boundaries. Synthetic performance says nothing about real-world efficacy.
