# Linux Internals Explained — Linux Ransomware Behavior Detection Lab

## What this program observes

The classifier does not subscribe to a kernel event source. It consumes a file that another lab component or the fixture generator produced. That separation is intentional: `event.v1` is input data, and an actor marked unknown remains unknown. This binary cannot infer a process from nearby timestamps.

## File I/O and timestamps

`std::ifstream`/`std::ofstream` wrap host file descriptors and close them through RAII. `std::getline` creates one string per line; the JSON parser checks whether that string exceeds 1 MiB afterward. Because `getline` may allocate the whole line first, a malicious oversized record can temporarily exceed the intended memory bound.

`parse_time` uses GNU/Linux `timegm` to convert a UTC broken-down time into epoch seconds, with one-second precision. It does not currently use a monotonic replay timer. A real replay clock must distinguish event-time order from local elapsed time (`CLOCK_MONOTONIC`) and specify late/missing-event behavior.

## Kernel event-source options

If a future collector uses inotify, the kernel returns filesystem notifications through a file descriptor, but may coalesce events, overflow, and does not identify a reliable actor. Fanotify has different privilege and filesystem requirements. Either source must carry coverage metadata so BHD can choose `unknown` instead of benign when evidence is incomplete.

There is no epoll, poll, io_uring, fanotify, eBPF, or BPF LSM code in the current executable. Do not imply these interfaces are implemented because the SRS discusses them as upstream event-source options.

## Failure and resource handling

Malformed JSON, bad required fields, invalid selected rule bounds, missing files/labels, or unwritable output produce an exception and nonzero exit. The corpus is accumulated before scoring, so the memory use scales with total records. Event cardinality is capped at one million, but per-window entity bounds and streaming retention are incomplete. Output replacement is not atomic.

## Official references

- [Linux inotify documentation](https://docs.kernel.org/filesystems/inotify.html), [`inotify(7)`](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [`clock_gettime(2)`](https://man7.org/linux/man-pages/man2/clock_gettime.2.html) for monotonic time
- [C++ file streams](https://en.cppreference.com/w/cpp/io/basic_ifstream.html) and [C++ time utilities](https://en.cppreference.com/w/cpp/chrono/c.html)
- [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259), [JSON Schema 2020-12](https://json-schema.org/draft/2020-12)
