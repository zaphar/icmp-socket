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
//! Ping an IPv4 address with an async datagram socket on tokio. Needs no
//! privileges on macOS, and on Linux when `net.ipv4.ping_group_range`
//! includes the user's group.
//!
//! `cargo run --features tokio --example async_ping4 -- 127.0.0.1`
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use icmp_socket::Icmpv4Message;
use icmp_socket::tokio::DgramSocket4;

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    let target: Ipv4Addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1".to_owned())
        .parse()
        .expect("argument must be an IPv4 address");
    let mut socket = DgramSocket4::open()?;

    for sequence in 0u16.. {
        let sent = Instant::now();
        socket.send_echo(target, sequence, &[0x20; 56]).await?;
        // Async receives have no timeout of their own; use the runtime's.
        let reply = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let (msg, from) = socket.recv_from().await?;
                // On macOS every datagram socket receives every reply, so
                // match on the identifier and sequence.
                if let Icmpv4Message::EchoReply {
                    identifier,
                    sequence: seq,
                    payload,
                    ..
                } = msg
                {
                    if from == target && identifier == socket.identifier() && seq == sequence {
                        return Ok::<_, std::io::Error>(payload.len());
                    }
                }
            }
        })
        .await;
        match reply {
            Ok(Ok(size)) => println!(
                "Ping {} seq={} time={:.3}ms size={}",
                target,
                sequence,
                sent.elapsed().as_secs_f64() * 1000.0,
                size
            ),
            Ok(Err(e)) => eprintln!("receive failed: {}", e),
            Err(_) => println!("Ping {} seq={} timed out", target, sequence),
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Ok(())
}
