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
//! On-the-wire tests of the raw sockets against a real kernel.
//!
//! Raw sockets need root (or `CAP_NET_RAW` on Linux), so these tests are
//! `#[ignore]`d. Run them with elevated privileges, e.g.
//! `sudo -E cargo test --test raw_loopback -- --ignored --test-threads=1`.
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use icmp_socket::*;

const LOCALHOST: Ipv4Addr = Ipv4Addr::LOCALHOST;
const LO6: Ipv6Addr = Ipv6Addr::LOCALHOST;

fn raw4() -> RawSocket4 {
    let mut socket =
        RawSocket4::bind(Ipv4Addr::UNSPECIFIED).expect("raw sockets need root or CAP_NET_RAW");
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket
}

fn raw6() -> RawSocket6 {
    let mut socket = RawSocket6::open().expect("raw sockets need root or CAP_NET_RAW");
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket
}

/// Receive until the v4 echo reply with this identifier and sequence.
fn await_reply4(socket: &mut RawSocket4, sequence: u16) {
    loop {
        let (msg, from) = socket.recv_from().expect("failed to receive a reply");
        // A raw socket also receives our own request on loopback.
        if let Icmpv4Message::EchoReply {
            identifier: 0xBEEF,
            sequence: seq,
            ..
        } = msg
        {
            if seq == sequence {
                assert_eq!(from, LOCALHOST);
                return;
            }
        }
    }
}

#[test]
#[ignore]
fn raw4_loopback_roundtrip() {
    let mut socket = raw4();
    let request = Icmpv4Message::echo_request(0xBEEF, 5, vec![0x20; 16]);
    socket.send_to(LOCALHOST, &request).unwrap();
    await_reply4(&mut socket, 5);
}

#[test]
#[ignore]
fn raw4_send_raw_sends_bytes_as_given() {
    let mut socket = raw4();
    let bytes = Icmpv4Message::echo_request(0xBEEF, 6, vec![1, 2, 3]).to_bytes();
    socket.send_raw(LOCALHOST, &bytes).unwrap();
    await_reply4(&mut socket, 6);
}

#[test]
#[ignore]
fn raw6_unbound_loopback_roundtrip() {
    let mut socket = raw6();
    // Unbound: the kernel chooses the source address and computes the
    // checksum.
    let request = Icmpv6Message::echo_request(0xBEEF, 5, vec![0x20; 16]);
    socket.send_to(LO6, &request).unwrap();
    loop {
        let (bytes, info) = socket.recv_raw().expect("failed to receive a reply");
        let msg = Icmpv6Message::parse(bytes).unwrap();
        if let Icmpv6Message::EchoReply {
            identifier: 0xBEEF,
            sequence: 5,
            ..
        } = msg
        {
            assert_eq!(info.source().addr, LO6);
            // RecvInfo gives the arrival address, which the ICMPv6
            // pseudo-header needs.
            let local = info.local_addr().expect("no arrival address");
            assert!(Icmpv6Message::verify_checksum(
                bytes,
                &info.source().addr,
                &local.addr
            ));
            return;
        }
    }
}
