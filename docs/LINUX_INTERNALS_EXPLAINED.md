# Linux Internals Explained — Linux Ransomware Behavior Detection Lab

## What this program observes

The classifier does not subscribe to a kernel event source. It consumes a file that another lab component or the fixture generator produced. That separation is intentional: `event.v1` is input data, and an actor marked unknown remains unknown. This binary cannot infer a process from nearby timestamps.

## File I/O and timestamps

`std::ifstream`/`std::ofstream` wrap host file descriptors and close them through RAII. `read_limited_line` reads one byte at a time into a reused `std::string` and stops at 1 MiB before appending more input. The importer also caps event ID, host ID, kind, and path lengths, limits total events, and checks unique host cardinality from the rules. These bounds constrain one record and selected indexes, but the corpus and normalized copy still reside in memory together.

`parse_time` uses GNU/Linux `timegm` to convert a UTC broken-down time into epoch seconds, with one-second precision. Replay checks per-host arrival order against a configured lateness tolerance, removes exact duplicates, marks conflicts/too-late input unknown, and sorts accepted events by event time. It evaluates a rolling interval at each distinct event second. It still does not use a separate wall-clock-paced monotonic timer, and cannot identify a missing source record without a sequence number. A streaming design would use `CLOCK_MONOTONIC` for local deadlines while keeping event timestamps as a separate clock domain.

## Kernel event-source options

If a future collector uses inotify, the kernel returns filesystem notifications through a file descriptor, but may coalesce events, overflow, and does not identify a reliable actor. Fanotify has different privilege and filesystem requirements. Either source must carry coverage metadata so BHD can choose `unknown` instead of benign when evidence is incomplete.

There is no epoll, poll, io_uring, fanotify, eBPF, or BPF LSM code in the current executable. Do not imply these interfaces are implemented because the SRS discusses them as upstream event-source options.

## Failure and resource handling

Malformed JSON, bad required fields, invalid rule bounds, missing files/labels, or unwritable output produce an exception and nonzero exit. The corpus is accumulated before scoring, so memory use scales with total records. Total events are capped at one million and host entities have a configurable bound, but streaming retention is not implemented. Output replacement is not atomic. Unknown/degraded coverage, conflicting IDs, and too-late records produce `unknown` rather than benign.

## Official references

- [Linux inotify documentation](https://docs.kernel.org/filesystems/inotify.html), [`inotify(7)`](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [`clock_gettime(2)`](https://man7.org/linux/man-pages/man2/clock_gettime.2.html) for monotonic time
- [C++ file streams](https://en.cppreference.com/w/cpp/io/basic_ifstream.html) and [C++ time utilities](https://en.cppreference.com/w/cpp/chrono/c.html)
- [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259), [JSON Schema 2020-12](https://json-schema.org/draft/2020-12)
