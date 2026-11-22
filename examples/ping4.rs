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
//! Ping an IPv4 address with a raw socket (needs root or CAP_NET_RAW).
//!
//! `cargo run --example ping4 -- 127.0.0.1`
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use icmp_socket::{Icmpv4Message, RawSocket4, RecvError};

/// The identifier in our echo requests. A raw socket receives ICMP packets
/// for every process on the host, so match replies on it and the sequence.
const IDENTIFIER: u16 = 42;

fn main() -> std::io::Result<()> {
    let target: Ipv4Addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1".to_owned())
        .parse()
        .expect("argument must be an IPv4 address");
    let mut socket = RawSocket4::open()?;
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;

    for sequence in 0u16.. {
        let request = Icmpv4Message::echo_request(IDENTIFIER, sequence, vec![0x20; 56]);
        let sent = Instant::now();
        socket.send_to(target, &request)?;
        loop {
            match socket.recv_from() {
                Ok((
                    Icmpv4Message::EchoReply {
                        identifier: IDENTIFIER,
                        sequence: seq,
                        payload,
                        ..
                    },
                    from,
                )) if from == target && seq == sequence => {
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
