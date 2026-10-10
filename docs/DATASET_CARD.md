# Dataset Card — Synthetic Behavior Fixtures

## Purpose

The fixture generator verifies parser, window, rule, serialization, and metric wiring for the Linux Ransomware Behavior Detection Lab. It is not a malware corpus and does not support real-world detection claims.

## Contents

Each test run creates eight benign synthetic scenarios (compiler build, git checkout, package install, backup, archive, IDE save, sync, and log rotation) and four synthetic suspicious patterns (rapid rewrite, mass rename, mass delete, and mixed burst). Records contain synthetic host IDs and `/sandbox/...` paths; no real file content is created or read.

## Labels and limitations

Labels are generated next to their corresponding synthetic records. The current generator does not create an independent development/holdout split or an immutable label manifest. Since data and labels are constructed together, the confusion matrix only checks pipeline wiring. There is no claimed precision, recall, false-positive rate, or false-negative rate for real systems.

## Integrity and change history

Every replay decision records SHA-256 of the exact input bytes and exact rules file bytes. This supports per-run byte identity but is not a signed manifest or an append-only change ledger. No canonical frozen dataset digest is published yet. Rule or fixture changes should be reviewed in version control, and any future held-out set must be separated before threshold tuning.

## Safety

The generator creates only NDJSON and CSV metadata under a new directory beneath an existing sandbox root. It does not execute ransomware or mutate a workload tree. Real host telemetry should remain local and undergo privacy review before sharing.
