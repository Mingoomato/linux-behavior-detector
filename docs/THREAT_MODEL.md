# Threat Model

## Assets and trust boundaries

- Input NDJSON, rules JSON, labels CSV, CLI paths, and generated fixture destination are untrusted.
- Host IDs, paths, event IDs, labels, and decisions can reveal operational or personal information.
- Rule/input digests and the serialized decision are evidence only when the evidence store itself is protected.
- The binary is an offline classifier. It does not monitor a system, stop a process, restore files, or attest an actor.

## Existing controls

- JSON lines are capped at 1 MiB, parser nesting at 32, event count at one million, and event field lengths, host count, rule count, feature vocabulary, and numeric bounds are limited.
- Duplicate JSON keys and invalid UTF-8 are rejected. Invalid records include source line numbers.
- Exact duplicate event IDs are deduplicated; conflicting IDs and late events degrade affected host decisions to `unknown`.
- Non-healthy event coverage and inadequate sample counts cannot produce a benign decision.
- Fixture generation requires a new output directory beneath a pre-existing sandbox root.
- Rules and input bytes are SHA-256 hashed; the input digest is checked again after parsing. Every result carries `simulation_only=true`.
- Unknown actor attribution is not inferred from timestamps or nearby process IDs.
- `replay --stream` opens a regular file with `O_NOFOLLOW`, hashes and reads the same descriptor, caps the same-second queue, active-window events/bytes, ID cache, event count, record size, and output size, and emits an explicit unknown decision when queue/window capacity drops evidence.
- Stream output is accumulated in a sibling mode-0600 temporary file and renamed into place only after a complete run and a matching final input hash; errors remove the temporary file and preserve an existing destination.

## Residual risks and failure modes

- The custom parser does not yet have a complete standards-conformance or fuzz record. Timestamp parsing now checks RFC 3339 offsets and calendar validity, but keeps only whole-second precision.
- A million-event input can consume substantial memory because source and normalized vectors coexist and the number of output windows is not independently capped.
- Stream mode deliberately rejects event-time regression and producer sequence metadata. It does not provide asynchronous producer backpressure or a watermark that safely accepts bounded disorder. The recent-ID cache is bounded to its retention interval; it cannot prove global uniqueness over an arbitrarily long feed.
- Label CSV parsing is simple; quoted values, invalid labels, and missing/extra label coverage require stronger checks.
- Hashes identify bytes but do not establish the source, signing authority, label correctness, immutable history, or independent holdout status. A separate trusted manifest and access-controlled evidence store are needed.
- Batch mode hashes by path before and after parsing, but a malicious writer could coordinate changes around those reads. Stream mode uses one open descriptor and compares content hashes and metadata before publishing output; directory replacement and hostile parent-directory races are outside this lab's path-hardening scope.
- Raw host identifiers and paths are emitted without pseudonymization. Keep generated and real evidence local and protect output permissions.
- The generated labels are paired with generated data. Their confusion matrix is not an efficacy estimate, and baseline thresholds must not be tuned and reported against the same fixture set as holdout results.

## Trust decisions

When provenance or coverage is incomplete, the engine returns `unknown`. A replay hash mismatch aborts; parser, rule, resource-bound, read, or write failures return a nonzero error. The program does not try to recover by inventing an actor or silently downgrading evidence.

Stream queue and active-window overflow are evidence-loss conditions, not ordinary capacity successes: dropped events are not scored and the host is marked `unknown` through the event-time window that could include the missing event. A later decision may become non-unknown only after that interval expires and new evidence supports it. Atomic rename prevents readers from seeing a partially written final path, but the containing directory is not synced, so the implementation makes no power-loss durability claim. These new stream controls have not yet been technically verified.
