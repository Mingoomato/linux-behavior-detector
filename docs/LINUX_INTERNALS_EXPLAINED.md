# Linux Internals Explained — Linux Ransomware Behavior Detection Lab

## What the binary observes

`bdetect` reads event records from ordinary files. It does not subscribe to a kernel event source, open monitored directories, or inspect process state. The event producer is outside this repository. Actor attribution remains unknown unless a trusted source explicitly supplies it.

## File descriptors and ownership

Batch commands use `std::ifstream` and `std::ofstream`, which own their underlying file resources through RAII. Stream replay instead opens its input with `open(2)` and reads through `read(2)` into a fixed 64 KiB buffer; `read_stream_line` builds at most one 1 MiB record. `pread(2)` hashes the same already-open descriptor without changing its sequential read offset. `fstat(2)` checks that it is a regular file and detects size, inode, timestamp, or content changes around replay. An `InputGuard` closes the descriptor on both normal and exceptional exits. `O_NOFOLLOW` protects the final input path component from symlink substitution; it does not pin or validate every parent directory.

The event vector owns the parsed strings. Normalization copies accepted records into another vector; hash maps and the evaluator use non-owning views/pointers whose lifetime is tied to those vectors. Hash contexts are owned by `std::unique_ptr` and release through `EVP_MD_CTX_free`.

## Event time and monotonic time

`parse_time` validates an RFC 3339 date, clock, fractional field, and explicit `Z` or numeric offset, then normalizes the represented instant to epoch seconds. Fractional digits are accepted but discarded, so distinct subsecond events in one second are ordered at one-second precision. Window boundaries and lateness use event time, not the host's wall clock. A selected 100,000-run Clang libFuzzer campaign covered the JSON parser under ASan/UBSan; the importer and timestamp parser still need dedicated fuzz targets and longer campaigns.

Optional `--speed` maps event-time offsets to `std::chrono::steady_clock` deadlines using `sleep_until` in both modes. The steady clock is monotonic and is not adjusted by wall-clock synchronization. Speed zero is fast/offline mode. Positive speed is only a replay pacing aid; it does not affect window membership or scores, and a scheduled wait above one hour is rejected. No direct `clock_gettime(2)` call appears in the source. On Linux, a standard-library implementation may obtain monotonic readings through platform runtime mechanisms, but that is an implementation detail.

## SHA-256 evidence

The executable calls OpenSSL EVP digest APIs to compute SHA-256 over the exact rules and input bytes. Rule bytes are bounded and parsed; datasets are hashed in fixed-size chunks. Batch mode hashes the input before and after parsing. Stream mode hashes the opened descriptor with `pread(2)` before processing and again afterward, and includes that digest in each decision record. The hash binds the report to bytes, but does not establish who created them, whether labels are correct, or whether a holdout set was kept separate.

## Upstream kernel interfaces

If a separate collector supplies events, Linux inotify delivers filesystem notifications through a file descriptor but can coalesce events, overflow, and lacks reliable process attribution. Fanotify can provide different access and permission events with privilege and filesystem constraints. eBPF tracing could add process context only under an explicitly validated source and kernel policy. None of inotify, fanotify, epoll, io_uring, eBPF, or BPF LSM is implemented here. Coverage gaps from an upstream source must remain visible and make decisions unknown.

## Concurrency and failure behavior

This program is single-threaded. Stream replay has a bounded in-memory queue for the current event-time second and a rolling active window; it is not an asynchronous producer queue and cannot apply backpressure to an external collector. Queue/window overflow drops an event and marks the host unknown for the interval in which the missing event could affect a window. The mode requires nondecreasing whole-second event time, rejects producer sequence metadata, and does not use `timerfd`, `epoll`, or a watermark to accept out-of-order input. Optional timing uses `std::chrono::steady_clock` so wall-clock adjustments do not affect replay pacing. Batch per-decision samples cover window aggregation and rule evaluation, while aggregate evaluation duration includes host/window index setup; neither includes input parsing, replay pacing, or serialization. Input files are capped at 512 MiB, event JSONL records at 1 MiB, and decision records at 64 MiB. Label CSV parsing is bounded to 1 MiB per logical record, two fields of at most 256 bytes each, and 100,000 labels; malformed quoting, invalid UTF-8, and control bytes fail closed. Rule validation fails before scoring on unsupported features/operators or invalid bounds. Evaluation prediction input is capped at 1,000,000 non-empty records; optional CSV/HTML timelines retain at most 100,000 compact rows. Rule-correlation analysis is capped at 1,000,000 decision records, 256 rules, and 10,000,000 pair updates. CSV output quotes each field and uses CRLF record separators. HTML values are escaped before insertion into static markup. During batch scoring, event strings are released after they fall outside the active time window; object shells and indexes remain. Late/conflicting events, sequence gaps/collisions, mixed sequenced/unsequenced source records, and non-healthy coverage produce unknown in batch replay. Stream output is written through a mode-0600 temporary file, synced, and renamed to the destination on success; a failed run removes the temporary file and preserves any existing destination. The parent directory is not synced, so a power-loss durability guarantee is not claimed. The current cap, report, correlation, and stream code has not yet been technically verified.

Dataset freezing uses Linux `open(2)` flags `O_CREAT|O_EXCL|O_NOFOLLOW` so an existing manifest or final-component symlink is not overwritten. It applies read-only mode with `fchmod(2)` and calls `fsync(2)` on the file. Audit opens its JSONL ledger with `O_APPEND|O_NOFOLLOW`, requires a regular owner-only file, takes an exclusive `flock(2)`, appends one bounded record, and calls `fdatasync(2)`. File descriptors are closed on normal and exceptional paths. Parent-directory synchronization and a cryptographic signature are not provided, so this is not power-loss-proof or administrator-resistant provenance. The manifest/ledger implementation has not been technically verified.

## Official references

- [C++ `steady_clock`](https://en.cppreference.com/w/cpp/chrono/steady_clock.html), [C++ file streams](https://en.cppreference.com/w/cpp/io/basic_ifstream.html)
- [`clock_gettime(2)`](https://man7.org/linux/man-pages/man2/clock_gettime.2.html)
- [`open(2)`](https://man7.org/linux/man-pages/man2/open.2.html), [`read(2)`](https://man7.org/linux/man-pages/man2/read.2.html), [`pread(2)`](https://man7.org/linux/man-pages/man2/pread.2.html), [`fstat(2)`](https://man7.org/linux/man-pages/man2/fstat.2.html), [`write(2)`](https://man7.org/linux/man-pages/man2/write.2.html), [`rename(2)`](https://man7.org/linux/man-pages/man2/rename.2.html), [`unlink(2)`](https://man7.org/linux/man-pages/man2/unlink.2.html), [`fsync(2)`](https://man7.org/linux/man-pages/man2/fsync.2.html), [`close(2)`](https://man7.org/linux/man-pages/man2/close.2.html)
- [OpenSSL EVP digest API](https://docs.openssl.org/3.0/man3/EVP_DigestInit/)
- [Linux inotify](https://docs.kernel.org/filesystems/inotify.html), [`fanotify(7)`](https://man7.org/linux/man-pages/man7/fanotify.7.html), [BPF LSM](https://docs.kernel.org/bpf/prog_lsm.html)
- [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339), [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259)
