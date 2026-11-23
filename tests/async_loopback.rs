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
//! On-the-wire tests of the async sockets against a real kernel, on each
//! built-in runtime. `#[ignore]`d like the blocking datagram tests; run with
//! `cargo test --all-features --test async_loopback -- --ignored --test-threads=1`.
#![cfg(all(feature = "tokio", feature = "async-io"))]
use std::net::{Ipv4Addr, Ipv6Addr};

use icmp_socket::*;

/// Send one echo request and wait for its reply on any runtime's socket.
macro_rules! round_trip {
    ($socket:expr, $dest:expr, $sequence:expr, $reply:path) => {{
        let mut socket = $socket;
        socket
            .send_echo($dest, $sequence, &[0x20; 16])
            .await
            .unwrap();
        loop {
            let (msg, _) = socket.recv_from().await.unwrap();
            if let $reply {
                identifier,
                sequence,
                ..
            } = msg
            {
                if identifier == socket.identifier() && sequence == $sequence {
                    break;
                }
            }
        }
    }};
}

#[test]
#[ignore]
fn tokio_dgram_round_trips() {
    let rt = ::tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap();
    rt.block_on(async {
        let timeout = std::time::Duration::from_secs(2);
        ::tokio::time::timeout(timeout, async {
            round_trip!(
                icmp_socket::tokio::DgramSocket4::bind(Ipv4Addr::UNSPECIFIED).unwrap(),
                Ipv4Addr::LOCALHOST,
                21,
                Icmpv4Message::EchoReply
            );
            round_trip!(
                icmp_socket::tokio::DgramSocket6::bind(Ipv6Addr::UNSPECIFIED).unwrap(),
                Ipv6Addr::LOCALHOST,
                22,
                Icmpv6Message::EchoReply
            );
        })
        .await
        .expect("no reply in time");
    });
}

#[test]
#[ignore]
fn async_io_dgram_round_trips() {
    ::async_io::block_on(async {
        round_trip!(
            icmp_socket::async_io::DgramSocket4::bind(Ipv4Addr::UNSPECIFIED).unwrap(),
            Ipv4Addr::LOCALHOST,
            23,
            Icmpv4Message::EchoReply
        );
        round_trip!(
            icmp_socket::async_io::DgramSocket6::bind(Ipv6Addr::UNSPECIFIED).unwrap(),
            Ipv6Addr::LOCALHOST,
            24,
            Icmpv6Message::EchoReply
        );
    });
}

/// The future of an async receive can move to another thread.
#[test]
fn tokio_futures_are_send() {
    fn assert_send<T: Send>(_: &T) {}
    let rt = ::tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();
    rt.block_on(async {
        if let Ok(mut socket) = icmp_socket::tokio::DgramSocket4::open() {
            assert_send(&socket.recv_from());
        }
    });
}
