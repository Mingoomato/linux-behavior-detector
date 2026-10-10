# Linux Internals Explained — Linux Ransomware Behavior Detection Lab

## What the binary observes

`bdetect` reads event records from ordinary files. It does not subscribe to a kernel event source, open monitored directories, or inspect process state. The event producer is outside this repository. Actor attribution remains unknown unless a trusted source explicitly supplies it.

## File descriptors and ownership

`std::ifstream` and `std::ofstream` provide buffered C++ stream operations over file descriptors (or equivalent platform handles). They acquire and release resources through RAII, including on exceptions. The code does not call `open(2)`, `read(2)`, or `close(2)` directly. `read_limited_line` reads one byte at a time through the stream interface and refuses to grow a record beyond 1 MiB. Current performance work should consider buffered bounded reads, while preserving the same cap and line-numbered failures.

The event vector owns the parsed strings. Normalization copies accepted records into another vector; hash maps and the evaluator use non-owning views/pointers whose lifetime is tied to those vectors. Hash contexts are owned by `std::unique_ptr` and release through `EVP_MD_CTX_free`.

## Event time and monotonic time

`parse_time` validates an RFC 3339 date, clock, fractional field, and explicit `Z` or numeric offset, then normalizes the represented instant to epoch seconds. Fractional digits are accepted but discarded, so distinct subsecond events in one second are ordered at one-second precision. Window boundaries and lateness use event time, not the host's wall clock. Parser fuzz coverage remains open.

Optional `--speed` maps event-time offsets to `std::chrono::steady_clock` deadlines using `sleep_until`. The steady clock is monotonic and is not adjusted by wall-clock synchronization. Speed zero is fast/offline mode. Positive speed is only a replay pacing aid; it does not affect window membership or scores, and a scheduled wait above one hour is rejected. No direct `clock_gettime(2)` call appears in the source. On Linux, a standard-library implementation may obtain monotonic readings through platform runtime mechanisms, but that is an implementation detail.

## SHA-256 evidence

The executable calls OpenSSL EVP digest APIs to compute SHA-256 over the exact rules and input bytes. Rule bytes are bounded and parsed; the potentially large dataset is hashed in fixed-size chunks. The input is hashed again after parsing to detect concurrent byte changes. A digest identifies bytes, but does not establish who created them, whether labels are correct, or whether a holdout set was kept separate.

## Upstream kernel interfaces

If a separate collector supplies events, Linux inotify delivers filesystem notifications through a file descriptor but can coalesce events, overflow, and lacks reliable process attribution. Fanotify can provide different access and permission events with privilege and filesystem constraints. eBPF tracing could add process context only under an explicitly validated source and kernel policy. None of inotify, fanotify, epoll, io_uring, eBPF, or BPF LSM is implemented here. Coverage gaps from an upstream source must remain visible and make decisions unknown.

## Concurrency and failure behavior

This program is single-threaded. There is no worker queue, lock, atomic state, or backpressure mechanism. Input parsing fails on malformed or oversized 1 MiB records, unsupported schema, invalid required fields, incomplete sequence metadata pairs, invalid sequence numbers, or event limits. Rule validation fails before scoring on unsupported features/operators or invalid bounds. Decision JSONL can carry up to 64 MiB of event evidence; larger decisions are rejected before serialization. Late/conflicting events, sequence gaps/collisions, mixed sequenced/unsequenced source records, and non-healthy coverage produce unknown. Sequence gaps are checked after the entire input batch is read; this is not a `timerfd`, `epoll`, or online watermark implementation. Large allowed corpora still retain both source and normalized vectors, so the cap does not guarantee a small memory footprint. Output is not atomically replaced.

## Official references

- [C++ `steady_clock`](https://en.cppreference.com/w/cpp/chrono/steady_clock.html), [C++ file streams](https://en.cppreference.com/w/cpp/io/basic_ifstream.html)
- [`clock_gettime(2)`](https://man7.org/linux/man-pages/man2/clock_gettime.2.html)
- [OpenSSL EVP digest API](https://docs.openssl.org/3.0/man3/EVP_DigestInit/)
- [Linux inotify](https://docs.kernel.org/filesystems/inotify.html), [`fanotify(7)`](https://man7.org/linux/man-pages/man7/fanotify.7.html), [BPF LSM](https://docs.kernel.org/bpf/prog_lsm.html)
- [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339), [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259)
