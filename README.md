# ICMP Sockets for both IPv4 and IPv6

An implementation of ICMP Sockets for both IPv4 and IPv6.

Sockets are opened unbound or bound to an address. Raw sockets send any message and need privileges; datagram ("ping") sockets send echo requests and need none on macOS, and on Linux when `net.ipv4.ping_group_range` allows it.

```rust,no_run
use std::net::Ipv4Addr;

use icmp_socket::RawSocket4;

let socket = RawSocket4::bind(Ipv4Addr::UNSPECIFIED).unwrap();
```

It can construct and parse the common ICMP packets for both ICMP4 and ICMP6.

```rust
use icmp_socket::{Icmpv4Message, Icmpv6Message};

let packet4 = Icmpv4Message::echo_request(42, 1, b"payload".to_vec());
let packet6 = Icmpv6Message::echo_request(42, 1, b"payload".to_vec());
```

# API Documentation

https://docs.rs/icmp-socket