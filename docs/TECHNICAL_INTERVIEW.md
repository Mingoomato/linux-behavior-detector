# Technical Defense — Linux Ransomware Behavior Detection Lab

Questions only; no answer key is included. Defend each decision with source and test evidence, then state limitations and alternatives.

## Code reading and data flow

1. Trace one JSONL record from `load_events` into a decision. Which fields are required and which are optional?
2. What guarantees does `Parser` in `json.hpp` provide about duplicate keys, nesting, string escapes, and input size?
3. Explain how `parse_time` converts the timestamp and what validation is missing.
4. How does `evaluate` choose each sliding-window endpoint and advance its left boundary? Which sets determine unique feature counts?
5. Why are pointers in the window map valid during evaluation? What change could invalidate them?
6. Which conditions force `unknown`, and why is that safer than benign?
7. What information does `write_decisions` preserve? What does `simulation_only` mean?

## Debugging and metrics

8. How does `normalize_events` treat an exact duplicate ID versus a conflicting duplicate, and how does each affect the minimum sample count?
9. What happens when an event falls outside the lateness tolerance? Why can a missing source record still be invisible?
10. Which denominator and label-validation checks should accompany TP/FP/TN/FN and `N/A` rates?
11. How would you reproduce deterministic replay and compare outputs while ignoring non-semantic metadata?
12. What happens when an input line exceeds the parser cap, and when may memory already have been allocated?

## Security and evaluation validity

13. Why must unknown actor attribution remain unknown rather than correlate nearby PIDs?
14. Which fields can contain personal data, and where are they emitted today?
15. Why do fixture metrics not estimate real-world ransomware detection efficacy?
16. How should degraded coverage and event-order loss affect a decision?
17. What threat is reduced by requiring generated fixtures beneath a sandbox root, and what path races remain?

## Design tradeoffs

18. Compare fixed UTC buckets, rolling event-time windows, and a watermark-based streaming design.
19. How would rule objects with ID/operator/threshold/weight/minimum count improve auditability? What validation risks follow?
20. How can development and holdout fixtures be separated and frozen to avoid tuning leakage?
21. When might inotify, fanotify, or eBPF be appropriate upstream, and what coverage limits accompany them?
22. Which next gate would reduce uncertainty most: parser fuzzing, late-event replay, dataset hashing, or a 100k-event resource test?

Owner mastery is not inferred from an automated smoke test; it requires direct evidence such as an independent exercise implementation and a reasoned defense.
