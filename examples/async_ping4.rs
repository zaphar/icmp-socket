// Copyright 2021 Jeremy Wall
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//! Async ICMPv4 ping example built on the smol runtime.
//!
//! This uses an unprivileged datagram (SOCK_DGRAM) socket so it can run
//! without root on platforms that allow it (macOS, and Linux when
//! `net.ipv4.ping_group_range` is configured). To use a raw socket instead,
//! swap `new_dgram_socket()` for `new()` and run with elevated privileges.
use std::{
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use icmp_socket::*;

fn main() -> std::io::Result<()> {
    let address = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1".to_owned());
    let parsed_addr = address
        .parse::<Ipv4Addr>()
        .expect("argument must be an IPv4 address");

    // NOTE: `use icmp_socket::*` brings the crate's own `smol` module into
    // scope, so reach the external smol crate explicitly with a leading `::`.
    ::smol::block_on(async move {
        // A datagram socket owns its identifier, so we only supply the
        // sequence and payload to `send`. Use `IcmpSocket4::new()` for a raw
        // socket (requires privileges), whose send takes a full packet.
        let mut socket = DgramIcmpSocket4::new()?.into_async()?;
        socket.bind(Ipv4Addr::new(0, 0, 0, 0)).await?;
        socket.set_timeout(Some(Duration::from_secs(1)));

        let mut sequence = 0u16;
        loop {
            let send_time = Instant::now();
            socket
                .send(
                    parsed_addr,
                    sequence,
                    vec![
                        0x20, 0x20, 0x75, 0x73, 0x74, 0x20, 0x61, 0x20, 0x66, 0x6c, 0x65, 0x73,
                        0x68, 0x20, 0x77, 0x6f, 0x75, 0x6e, 0x64, 0x20, 0x20, 0x74, 0x69, 0x73,
                        0x20, 0x62, 0x75, 0x74, 0x20, 0x61, 0x20, 0x73, 0x63, 0x72, 0x61, 0x74,
                        0x63, 0x68, 0x20, 0x20, 0x6b, 0x6e, 0x69, 0x67, 0x68, 0x74, 0x73, 0x20,
                        0x6f, 0x66, 0x20, 0x6e, 0x69, 0x20, 0x20, 0x20,
                    ],
                )
                .await?;

            // Read replies until we see our own destination or time out.
            loop {
                match socket.rcv_from().await {
                    Ok((resp, sock_addr)) => {
                        let addr = match sock_addr.as_socket_ipv4() {
                            Some(a) => *a.ip(),
                            None => continue,
                        };
                        if addr != parsed_addr {
                            continue;
                        }
                        if !resp.verify_checksum() {
                            eprintln!("Discarding packet with invalid checksum");
                            continue;
                        }
                        if let Icmpv4Message::EchoReply {
                            identifier,
                            sequence: seq,
                            payload,
                        } = resp.message
                        {
                            // Other sockets' replies can arrive here too, e.g.
                            // on macOS, where every datagram ICMP socket
                            // receives every reply.
                            if identifier != socket.identifier() || seq != sequence {
                                continue;
                            }
                            let elapsed = Instant::now() - send_time;
                            println!(
                                "Ping {} seq={} time={}ms size={}",
                                addr,
                                seq,
                                (elapsed.as_micros() as f64) / 1000.0,
                                payload.len()
                            );
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("{:?}", e);
                        break;
                    }
                }
            }
            ::smol::Timer::after(Duration::from_secs(1)).await;
            sequence = sequence.wrapping_add(1);
        }
    })
}
