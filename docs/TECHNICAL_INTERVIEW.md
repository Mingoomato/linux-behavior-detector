# Technical Defense — Linux Ransomware Behavior Detection Lab

Questions only; no answer key is provided. Use the source, synthetic evidence, and test output to defend each response. State uncertainty and limitations explicitly.

## Code reading and data flow

1. Trace one event line from `read_limited_line` through `load_events` and `normalize_events` to the decision that references its ID.
2. Which event fields are required by the importer, which are copied into `Event`, and which are intentionally ignored?
3. What guarantees and limitations does `bdetect::json::Parser` have around duplicate keys, nesting, UTF-8, Unicode escapes, and numeric parsing?
4. How does `parse_time` currently interpret timestamps, and which valid RFC 3339 values or invalid calendar inputs does it mishandle?
5. Explain how `normalize_events` treats an exact duplicate ID, a conflicting duplicate ID, and an event outside the lateness tolerance.
6. How are the sliding window's left/right boundaries chosen, and why is the window inclusive at its end?
7. Which feature sets feed each available rule feature? How does the rule's operator and minimum sample count affect a decision?
8. Reconstruct a decision score from `reasons[]`. What evidence would you need to verify the final `score_cutoff` result?
9. Why are the non-owning `string_view` indexes and event pointers valid during normalization/evaluation? What mutation could invalidate them?
10. How is the decision ID formed, and what collision or stability properties does that scheme have?

## Debugging and verification

11. A replay with `--speed 10` takes longer but produces different decisions. Which event-time and monotonic-time paths would you inspect first?
12. How can a test prove that configured rule weights affect both score and explanation rather than only output metadata?
13. What exact bytes do `ruleset_sha256` and `dataset_sha256` cover? What does the before/after input hash check detect, and what does it not detect?
14. What conditions lead to `unknown`, and could any currently produce a misleading `coverage=observed` value?
15. Why must `producer_session_id` and `producer_sequence` appear as a pair, and why is the gap key `(host, source, session)` rather than just `host`?
16. How would you test 10-, 30-, and 60-second boundary cases, including an event exactly at the left edge?
17. What happens on an oversized line, a line with invalid UTF-8, an invalid rule operator, or a missing output directory?
18. Why can one million accepted records still exceed a practical memory budget? Which structures duplicate or retain the data?

## Security and evaluation validity

19. Why is correlating an event to a nearby PID unsafe when the upstream source does not attest process identity?
20. Which emitted fields may contain personal information, and how would pseudonymization change the ability to investigate a result?
21. What security properties does placing generated fixtures under a sandbox root provide? Which time-of-check/time-of-use or partial-write risks remain?
22. Why are generated fixture TP/FP/TN/FN counts a pipeline check rather than a real-world efficacy estimate?
23. How should conflicting IDs, late evidence, and unhealthy coverage influence both `decision` and `coverage` output?
24. What can a SHA-256 digest establish, and why is it not by itself proof of an untampered dataset history or honest labels?

## Design tradeoffs

25. Compare the current whole-corpus batch normalizer with a bounded streaming watermark and queue. What late-event contract would streaming require?
26. Compare fast offline replay, a paced monotonic timeline, and a fully virtual clock. Which should be used for deterministic tests and why?
27. What would a frozen development/holdout manifest need to record to avoid tuning leakage? Where would the rule hash fit?
28. When could inotify, fanotify, or eBPF be a useful upstream source, and what coverage, privilege, or attribution limits would remain?
29. Which change would most reduce uncertainty before claiming research value: timestamp validation, source sequence gaps, parser fuzzing, independent data, or 100k resource measurement? Defend your ordering.
30. What alternative rule or statistical model could represent interactions between features, and what data and calibration evidence would it require?
31. Why does the sequence audit sort numeric sequence values instead of event timestamps, and what assumptions does that make about a producer?
32. What should happen when two different event IDs claim one sequence number? How would an exact retransmission with one event ID differ?
33. Which decisions become `unknown` after a batch-level sequence gap is found? How would an interval-scoped online watermark change the design and its resource lifetimes?
34. Why does mixing sequenced and unsequenced records for the same host/source degrade coverage, while a source that is wholly unsequenced remains under the legacy behavior?
35. How does `read_csv_record` distinguish escaped quotes from a closing quote, and which resource limits apply to a logical multiline record?
36. How is nearest-rank p95 computed from the optional stats sidecar, what work is excluded, and how would you check that enabling it leaves decision bytes unchanged?

Automated build and test status does not establish the owner's personal mastery. That status remains unassessed without direct evidence from an independent reproduction or technical defense.
