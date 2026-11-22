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
//! On-the-wire tests for the raw sockets against a real kernel.
//!
//! Raw sockets need root (or `CAP_NET_RAW` on Linux), so these tests are
//! `#[ignore]`d. Run them with elevated privileges, e.g.
//! `sudo -E cargo test --test raw_loopback -- --ignored --test-threads=1`.
use std::net::Ipv6Addr;
use std::time::Duration;

use icmp_socket::packet::WithEchoRequest;
use icmp_socket::*;

#[test]
#[ignore]
fn raw6_unbound_loopback_roundtrip() {
    let lo = Ipv6Addr::LOCALHOST;
    let mut socket = IcmpSocket6::new().expect("raw sockets need root or CAP_NET_RAW");
    socket.set_timeout(Some(Duration::from_secs(2)));

    // The socket is not bound: the kernel chooses the source address and
    // computes the checksum.
    let packet = Icmpv6Packet::with_echo_request(0xBEEF, 5, vec![0x20; 16]).unwrap();
    socket.send_to(lo, packet).expect("failed to send");

    loop {
        let (resp, addr) = socket.rcv_from().expect("failed to receive a reply");
        let from = *addr
            .as_socket_ipv6()
            .expect("reply was not an IPv6 address")
            .ip();
        if from != lo {
            continue;
        }
        // Both ends are ::1, so the pseudo-header is known and the checksum
        // the kernel computed can be checked.
        assert!(
            resp.verify_checksum(&lo, &lo),
            "packet from ::1 failed checksum verification: {:?}",
            resp
        );
        if let Icmpv6Message::EchoReply {
            identifier: 0xBEEF,
            sequence: 5,
            ..
        } = resp.message
        {
            return;
        }
    }
}
