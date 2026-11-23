# Contributing

## Tests

`cargo test --all-features` runs the unit, property and doc tests.

The tests against a real kernel are `#[ignore]`d, because they need
permissions or a network:

| Command | Needs |
|---|---|
| `cargo test --all-features --test loopback_ping --test async_loopback -- --ignored --test-threads=1` | ICMP datagram sockets: on Linux, `net.ipv4.ping_group_range` must include your group |
| `sudo -E cargo test --test raw_loopback -- --ignored --test-threads=1` | root (or `CAP_NET_RAW` on Linux) |
| `cargo test --all-features --test network -- --ignored --test-threads=1` | a path to the internet; not run in CI |

On Linux the raw tests also run without root in a user and network
namespace: build them with `cargo test --test raw_loopback --no-run`, then run
the test binary with `unshare -rn sh -c "ip link set lo up && <binary> --ignored --test-threads=1"`.
