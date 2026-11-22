# ICMP Sockets for both IPv4 and IPv6

An implementation of ICMP Sockets for both IPv4 and IPv6.

Sockets can be created from IP addresses. IPv4 addresses will construct ICMP4 sockets. IPv6 will construct ICMP6 sockets.

```rust,no_run
use std::convert::TryFrom;
use std::net::Ipv4Addr;

use icmp_socket::IcmpSocket4;

let parsed_addr = "127.0.0.1".parse::<Ipv4Addr>().unwrap();
let socket = IcmpSocket4::try_from(parsed_addr).unwrap();
```

It can construct and parse the common ICMP packets for both ICMP4 and ICMP6.

```rust
use icmp_socket::{Icmpv4Message, Icmpv6Message};

let packet4 = Icmpv4Message::echo_request(42, 1, b"payload".to_vec());
let packet6 = Icmpv6Message::echo_request(42, 1, b"payload".to_vec());
```

# API Documentation

https://docs.rs/icmp-socket