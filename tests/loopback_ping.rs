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
//! On-the-wire tests of the datagram sockets against a real kernel.
//!
//! These check the behavior the crate makes the same on every system: Linux
//! datagram sockets deliver replies without an IPv4 header and macOS ones
//! with it, the identifier comes from different places, and so on. They are
//! `#[ignore]`d because they need working ICMP datagram sockets (on Linux,
//! `net.ipv4.ping_group_range` must include the user's group). Run them with
//! `cargo test --test loopback_ping -- --ignored --test-threads=1`.
use std::net::Ipv4Addr;
use std::time::Duration;

use icmp_socket::*;

const LOCALHOST: Ipv4Addr = Ipv4Addr::LOCALHOST;

fn socket() -> DgramSocket4 {
    let mut socket = DgramSocket4::bind(Ipv4Addr::UNSPECIFIED).unwrap_or_else(|e| {
        panic!(
            "could not open an ICMP datagram socket ({}); on Linux set \
             net.ipv4.ping_group_range to include this user's group",
            e
        )
    });
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket
}

/// Receive until our own reply with `sequence` arrives.
fn await_reply(socket: &mut DgramSocket4, sequence: u16) -> Icmpv4Message {
    loop {
        let (msg, from) = socket.recv_from().expect("failed to receive a reply");
        if from != LOCALHOST {
            continue;
        }
        if let Icmpv4Message::EchoReply {
            identifier,
            sequence: seq,
            ..
        } = msg
        {
            if identifier == socket.identifier() && seq == sequence {
                return msg;
            }
        }
    }
}

#[test]
#[ignore]
fn dgram_loopback_roundtrip() {
    let mut socket = socket();
    socket.send_echo(LOCALHOST, 1, &[0x20; 16]).unwrap();
    match await_reply(&mut socket, 1) {
        Icmpv4Message::EchoReply { payload, .. } => assert_eq!(payload, vec![0x20; 16]),
        other => panic!("expected an echo reply, got {:?}", other),
    }
}

#[test]
#[ignore]
fn dgram_message_too_large_is_truncated() {
    let mut socket = socket();
    // An 8 byte maximum cannot hold the 40 byte reply.
    socket.set_max_message_size(8);
    socket.send_echo(LOCALHOST, 2, &[0x20; 32]).unwrap();
    match socket.recv_from() {
        Err(RecvError::Truncated { buf_size: 8 }) => {}
        other => panic!("expected a truncation error, got {:?}", other),
    }
}

#[test]
#[ignore]
fn dgram_message_of_exactly_the_maximum_fits() {
    let mut socket = socket();
    // The reply is an 8 byte ICMP header and a 32 byte payload. The maximum
    // counts ICMP bytes on every system, although macOS also delivers the
    // IPv4 header.
    socket.set_max_message_size(40);
    socket.send_echo(LOCALHOST, 3, &[0x20; 32]).unwrap();
    await_reply(&mut socket, 3);
}

#[test]
#[ignore]
fn dgram_read_timeout_is_timeout() {
    let mut socket = socket();
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    match socket.recv_from() {
        Err(RecvError::Timeout) => {}
        other => panic!("expected a timeout with nothing sent, got {:?}", other),
    }
}

#[test]
#[ignore]
fn dgram_identifier_after_send_without_bind() {
    let mut socket = DgramSocket4::open().unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    // On Linux the kernel binds the socket on this send and puts its new
    // local port into the identifier.
    socket.send_echo(LOCALHOST, 4, &[0x20; 16]).unwrap();
    await_reply(&mut socket, 4);
    if cfg!(target_os = "macos") {
        assert_eq!(socket.identifier(), std::process::id() as u16);
    }
}

#[test]
#[ignore]
fn dgram_recv_with_info_reports_the_packet() {
    let mut socket = socket();
    socket.send_echo(LOCALHOST, 5, &[0x20; 16]).unwrap();
    loop {
        let (msg, info) = socket.recv_with_info().unwrap();
        if let Icmpv4Message::EchoReply { sequence: 5, .. } = msg {
            assert_eq!(info.source(), LOCALHOST);
            assert_eq!(info.local_addr(), Some(LOCALHOST));
            assert!(info.hop_limit().is_some(), "{:?}", info);
            assert!(info.interface_index().is_some(), "{:?}", info);
            return;
        }
    }
}

#[test]
#[ignore]
fn dgram_recv_raw_returns_icmp_bytes() {
    let mut socket = socket();
    socket.send_echo(LOCALHOST, 6, &[0x20; 16]).unwrap();
    loop {
        let (bytes, info) = socket.recv_raw().unwrap();
        // ICMP bytes on every system: no IPv4 header in front.
        let msg = Icmpv4Message::parse(bytes).unwrap();
        if let Icmpv4Message::EchoReply { sequence: 6, .. } = msg {
            assert!(Icmpv4Message::verify_checksum(bytes));
            assert_eq!(info.source(), LOCALHOST);
            return;
        }
    }
}

#[test]
#[ignore]
fn dgram_send_options_apply_to_one_send() {
    let mut socket = socket();
    socket
        .send_echo_with_options(LOCALHOST, 7, &[0x20; 8], &SendOptions::new().hop_limit(9))
        .unwrap();
    await_reply(&mut socket, 7);
    socket.send_echo(LOCALHOST, 8, &[0x20; 8]).unwrap();
    await_reply(&mut socket, 8);
}

#[test]
#[ignore]
fn dgram_type_filter_drops_blocked_types() {
    let mut socket = socket();
    socket
        .set_type_filter(&TypeFilter::pass_all().block(icmpv4::msg_type::ECHO_REPLY))
        .unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    socket.send_echo(LOCALHOST, 10, &[0x20; 8]).unwrap();
    match socket.recv_from() {
        Err(RecvError::Timeout) => {}
        other => panic!("the reply should have been dropped, got {:?}", other),
    }
    socket.set_type_filter(&TypeFilter::pass_all()).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket.send_echo(LOCALHOST, 11, &[0x20; 8]).unwrap();
    await_reply(&mut socket, 11);
}

#[test]
#[ignore]
fn dgram6_loopback_roundtrip() {
    let lo = std::net::Ipv6Addr::LOCALHOST;
    let mut socket = DgramSocket6::bind(std::net::Ipv6Addr::UNSPECIFIED)
        .unwrap_or_else(|e| panic!("could not open an ICMPv6 datagram socket ({})", e));
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket.send_echo(lo, 12, &[0x20; 16]).unwrap();
    loop {
        let (msg, info) = socket.recv_with_info().unwrap();
        if let Icmpv6Message::EchoReply {
            identifier,
            sequence: 12,
            payload,
            ..
        } = msg
        {
            assert_eq!(identifier, socket.identifier());
            assert_eq!(payload, vec![0x20; 16]);
            assert_eq!(info.source().addr, lo);
            assert_eq!(info.local_addr().map(|a| a.addr), Some(lo));
            assert!(info.hop_limit().is_some());
            return;
        }
    }
}

#[test]
#[ignore]
fn dgram_multicast_hop_limit_applies_to_one_send() {
    use socket2::SockRef;
    let group = Ipv4Addr::new(224, 0, 0, 1);
    let mut socket = socket();
    // The socket sets the option before it sends, so a host with no
    // multicast route (e.g. the GitHub macOS runner) still tests it.
    let sent = |result: std::io::Result<()>| match result {
        Err(e) if e.kind() != std::io::ErrorKind::HostUnreachable => panic!("{e}"),
        _ => {}
    };
    let unicast = SockRef::from(&socket).ttl_v4().unwrap();
    let multicast = SockRef::from(&socket).multicast_ttl_v4().unwrap();
    // A multicast destination takes the multicast option, not the unicast
    // one.
    sent(socket.send_echo_with_options(group, 30, &[0; 8], &SendOptions::new().hop_limit(7)));
    assert_eq!(SockRef::from(&socket).multicast_ttl_v4().unwrap(), 7);
    assert_eq!(SockRef::from(&socket).ttl_v4().unwrap(), unicast);
    // A plain send restores the default.
    sent(socket.send_echo(group, 31, &[0; 8]));
    assert_eq!(
        SockRef::from(&socket).multicast_ttl_v4().unwrap(),
        multicast
    );
}
