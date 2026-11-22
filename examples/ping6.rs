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
//! Ping an IPv6 address with a raw socket (needs root or CAP_NET_RAW).
//!
//! `cargo run --example ping6 -- ::1` or, for a link-local address,
//! `cargo run --example ping6 -- fe80::1%en0`.
use std::time::{Duration, Instant};

use icmp_socket::{Icmpv6Message, RawSocket6, RecvError, ScopedIpv6Addr};

/// The identifier in our echo requests. A raw socket receives ICMPv6
/// packets for every process on the host, so match replies on it and the
/// sequence.
const IDENTIFIER: u16 = 42;

fn main() -> std::io::Result<()> {
    let target: ScopedIpv6Addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "::1".to_owned())
        .parse()
        .expect("argument must be an IPv6 address, optionally with %interface");
    let mut socket = RawSocket6::open()?;
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;

    for sequence in 0u16.. {
        let request = Icmpv6Message::echo_request(IDENTIFIER, sequence, vec![0x20; 56]);
        let sent = Instant::now();
        socket.send_to(target, &request)?;
        loop {
            match socket.recv_from() {
                Ok((
                    Icmpv6Message::EchoReply {
                        identifier: IDENTIFIER,
                        sequence: seq,
                        payload,
                        ..
                    },
                    from,
                )) if from.addr == target.addr && seq == sequence => {
                    println!(
                        "Ping {} seq={} time={:.3}ms size={}",
                        from,
                        seq,
                        sent.elapsed().as_secs_f64() * 1000.0,
                        payload.len()
                    );
                    break;
                }
                Ok(_) => continue, // someone else's packet
                Err(RecvError::Timeout) => {
                    println!("Ping {} seq={} timed out", target, sequence);
                    break;
                }
                Err(e) => eprintln!("receive failed: {}", e),
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    Ok(())
}
