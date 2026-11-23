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
//! Tests that need a network path to the internet. Not run in CI. Run them
//! with `cargo test --test network -- --ignored --test-threads=1`.
use std::net::Ipv4Addr;
use std::time::Duration;

use icmp_socket::*;

/// An outside address: the first router on the path answers a hop limit of
/// 1 with Time Exceeded.
const OUTSIDE: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

#[test]
#[ignore]
fn dgram_time_exceeded_arrives_as_a_message() {
    let mut socket = DgramSocket4::bind(Ipv4Addr::UNSPECIFIED).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    socket
        .send_echo_with_options(OUTSIDE, 9, &[0x20; 16], &SendOptions::new().hop_limit(1))
        .unwrap();
    loop {
        let (msg, from) = socket
            .recv_from()
            .expect("no Time Exceeded from the first router");
        if let Icmpv4Message::TimeExceeded { code, original, .. } = msg {
            assert_eq!(code, icmpv4::time_exceeded_code::TTL);
            assert_ne!(from, OUTSIDE);
            assert!(!original.is_empty());
            // Where the system delivers the original IPv4 header (macOS; on
            // Linux datagram sockets `original` starts at our ICMP message),
            // its total length is as sent: 20 + 8 + 16 bytes, big-endian.
            if original[0] >> 4 == 4 {
                assert_eq!(&original[2..4], &[0, 44]);
            }
            return;
        }
    }
}

/// The same through tokio: on Linux the Time Exceeded waits in the error
/// queue, which signals only error readiness.
#[cfg(feature = "tokio")]
#[test]
#[ignore]
fn tokio_dgram_time_exceeded_arrives_as_a_message() {
    let rt = ::tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut socket = icmp_socket::tokio::DgramSocket4::bind(Ipv4Addr::UNSPECIFIED).unwrap();
        socket
            .send_echo_with_options(OUTSIDE, 9, &[0x20; 16], &SendOptions::new().hop_limit(1))
            .await
            .unwrap();
        ::tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let (Icmpv4Message::TimeExceeded { .. }, _) = socket.recv_from().await.unwrap() {
                    return;
                }
            }
        })
        .await
        .expect("no Time Exceeded from the first router");
    });
}
