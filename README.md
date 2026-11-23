# icmp-socket

ICMP and ICMPv6 sockets and messages for Rust, on Linux and macOS.

- **Every ICMP message type.** `Icmpv4Message` and `Icmpv6Message` have a
  variant for every type in the IANA registries, and option lists (Neighbor
  Discovery, RFC 4884 extensions, RPL) have a codec.
- **Raw and datagram sockets** for both protocols, blocking or async.
- **The same behavior on every supported system.** The crate hides the
  differences between the kernels (see below).

## Sockets

Raw sockets (`RawSocket4`, `RawSocket6`) send any message and receive every
ICMP packet for the host; they need root, or `CAP_NET_RAW` on Linux.
Datagram ("ping") sockets (`DgramSocket4`, `DgramSocket6`) send echo requests
and need no privileges on macOS, and on Linux when `net.ipv4.ping_group_range`
includes the user's group.

```rust,no_run
use std::net::Ipv4Addr;
use std::time::Duration;

use icmp_socket::{DgramSocket4, Icmpv4Message};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut socket = DgramSocket4::open()?;
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;
    socket.send_echo(Ipv4Addr::LOCALHOST, 1, b"ping")?;
    let (reply, from) = socket.recv_from()?;
    if let Icmpv4Message::EchoReply { identifier, sequence: 1, .. } = reply {
        println!("reply from {} with identifier {}", from, identifier);
    }
    Ok(())
}
```

Per-send options (`SendOptions`, e.g. the hop limit for a traceroute),
receive metadata (`RecvInfo`: hop limit, arrival address and interface),
`recv_raw` and `send_raw` for bytes as they are, and a `TypeFilter` are on
every socket.

## Messages

```rust
use icmp_socket::{Icmpv4Message, Icmpv6Message};

let request = Icmpv4Message::echo_request(42, 1, b"payload".to_vec());
let bytes = request.to_bytes(); // with the checksum
assert!(Icmpv4Message::verify_checksum(&bytes));
assert_eq!(Icmpv4Message::parse(&bytes).unwrap(), request);

// The ICMPv6 checksum covers the IPv6 addresses.
let lo = std::net::Ipv6Addr::LOCALHOST;
let bytes = Icmpv6Message::echo_request(42, 1, b"payload".to_vec()).to_bytes(&lo, &lo);
assert!(Icmpv6Message::verify_checksum(&bytes, &lo, &lo));
```

## Features

| Feature | Adds |
|---|---|
| `async` | `AsyncRawSocket4`, `AsyncRawSocket6`, `AsyncDgramSocket4`, `AsyncDgramSocket6` and the `Runtime` trait |
| `tokio` | the tokio runtime (`icmp_socket::tokio::DgramSocket4`, ...); enables `async` |
| `async-io` | the async-io runtime (`icmp_socket::async_io::DgramSocket4`, ...); enables `async` |

No feature is on by default. For another runtime, implement `Runtime`, or
drive the I/O-free state machines in `icmp_socket::machine` yourself.

## Behavior across systems

Each socket type behaves the same on Linux and macOS. The crate hides, for
example, whether the kernel delivers the IPv4 header, who sets the datagram
socket's identifier, and how Linux reports ICMP errors to datagram sockets
(its error queue). Giving callers control of such OS mechanisms is not a goal
of this crate; for OS-level control, use the socket's descriptor (`AsFd`, for
example with `socket2::SockRef`).

The differences that remain:

- **Datagram identifier:** on Linux it is the socket's local port, unique per
  socket. On macOS it is the process ID, so two datagram sockets in one
  process share it, and every datagram socket receives every reply: filter
  replies by identifier and sequence.
- **ICMP errors on Linux datagram sockets** arrive with `original` holding
  the ICMP message that was sent, without its IPv4 header.
- **Link-local IPv6 destinations without a scope ID** (e.g. `fe80::1` with
  scope 0): macOS fails the send; Linux picks an interface itself. Give a
  scope ID (`"fe80::1%en0".parse::<ScopedIpv6Addr>()`) for the same behavior
  on both.

## Versioning

- The public enums are exhaustive on purpose: a new message type, variant or
  error case is a breaking change and comes in a major release, so callers
  see every state at compile time. ICMP types assigned after a release parse
  as `Other` until then.
- The minimum supported Rust version is 1.85. Raising it is not a breaking
  change and can happen in a minor release.

## API documentation

<https://docs.rs/icmp-socket>
