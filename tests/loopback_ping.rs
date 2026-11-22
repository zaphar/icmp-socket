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
//! On-the-wire smoke test that validates the datagram receive path against a
//! real kernel.
//!
//! This is where our cross-platform assumption is actually exercised: Linux
//! datagram sockets deliver ICMP replies without an IPv4 header while macOS
//! includes it, and `parse_auto` must decode both. It is `#[ignore]`d because
//! it needs a working ICMP datagram socket (on Linux that means
//! `net.ipv4.ping_group_range` must include the running user's gid). Run it
//! explicitly with `cargo test -- --ignored`.
use std::net::Ipv4Addr;
use std::time::Duration;

use icmp_socket::*;

#[test]
#[ignore]
fn dgram_loopback_roundtrip() {
    let localhost = Ipv4Addr::new(127, 0, 0, 1);
    let mut socket = match DgramIcmpSocket4::new() {
        Ok(s) => s,
        Err(e) => panic!(
            "could not open an ICMP datagram socket ({}); on Linux set \
             net.ipv4.ping_group_range to include this user's gid",
            e
        ),
    };
    socket
        .bind(Ipv4Addr::new(0, 0, 0, 0))
        .expect("failed to bind");
    socket.set_timeout(Some(Duration::from_secs(2)));

    socket
        .send(localhost, 1, vec![0x20; 16])
        .expect("failed to send");

    // Read until we see the reply for our destination or time out. The kernel
    // may rewrite the identifier on datagram sockets, so match on the reply
    // type and sequence rather than the identifier.
    loop {
        let (resp, addr) = socket.rcv_from().expect("failed to receive a reply");
        let from = *addr
            .as_socket_ipv4()
            .expect("reply was not an IPv4 address")
            .ip();
        if from != localhost {
            continue;
        }
        // The reply came from a real kernel; its ICMP checksum must verify.
        assert!(
            resp.verify_checksum(),
            "loopback reply failed checksum verification"
        );
        // Match our own sequence; ignore any stray ICMP on the loopback
        // interface (on macOS datagram sockets share identifier 0).
        if let Icmpv4Message::EchoReply { sequence, .. } = resp.message {
            if sequence == 1 {
                return;
            }
        }
    }
}

#[test]
#[ignore]
fn dgram_recv_buffer_truncation() {
    let localhost = Ipv4Addr::new(127, 0, 0, 1);
    let mut socket = match DgramIcmpSocket4::new() {
        Ok(s) => s,
        Err(e) => panic!("could not open an ICMP datagram socket ({})", e),
    };
    socket
        .bind(Ipv4Addr::new(0, 0, 0, 0))
        .expect("failed to bind");
    socket.set_timeout(Some(Duration::from_secs(2)));

    // An 8 byte buffer cannot hold the echo reply, so rcv_from must report a
    // truncation error rather than a partial packet.
    socket.set_read_buffer_size(8);
    socket
        .send(localhost, 1, vec![0x20; 32])
        .expect("failed to send");
    let err = socket
        .rcv_from()
        .expect_err("expected a truncation error with an 8 byte buffer");
    assert!(
        err.to_string().contains("truncat"),
        "expected a truncation error, got: {}",
        err
    );

    // With a large buffer the same exchange succeeds.
    socket.set_read_buffer_size(2048);
    socket
        .send(localhost, 2, vec![0x20; 32])
        .expect("failed to send");
    loop {
        let (resp, addr) = socket.rcv_from().expect("failed to receive a reply");
        if *addr
            .as_socket_ipv4()
            .expect("reply was not an IPv4 address")
            .ip()
            != localhost
        {
            continue;
        }
        if let Icmpv4Message::EchoReply { sequence, .. } = resp.message {
            if sequence == 2 {
                return;
            }
        }
    }
}

#[test]
#[ignore]
fn dgram_recv_buffer_exact_fit() {
    let localhost = Ipv4Addr::new(127, 0, 0, 1);
    let mut socket = match DgramIcmpSocket4::new() {
        Ok(s) => s,
        Err(e) => panic!("could not open an ICMP datagram socket ({})", e),
    };
    socket
        .bind(Ipv4Addr::new(0, 0, 0, 0))
        .expect("failed to bind");
    socket.set_timeout(Some(Duration::from_secs(2)));

    // The reply is an 8 byte ICMP header and a 32 byte payload. macOS also
    // delivers the 20 byte IPv4 header; Linux does not.
    let reply_len = if cfg!(target_os = "macos") { 60 } else { 40 };
    socket.set_read_buffer_size(reply_len);
    socket
        .send(localhost, 3, vec![0x20; 32])
        .expect("failed to send");
    loop {
        let (resp, addr) = socket
            .rcv_from()
            .expect("a reply that fills the buffer exactly is not truncated");
        if *addr
            .as_socket_ipv4()
            .expect("reply was not an IPv4 address")
            .ip()
            != localhost
        {
            continue;
        }
        if let Icmpv4Message::EchoReply { sequence, .. } = resp.message {
            if sequence == 3 {
                return;
            }
        }
    }
}

#[test]
#[ignore]
fn dgram_recv_timeout_is_timed_out() {
    let mut socket = match DgramIcmpSocket4::new() {
        Ok(s) => s,
        Err(e) => panic!("could not open an ICMP datagram socket ({})", e),
    };
    socket
        .bind(Ipv4Addr::new(0, 0, 0, 0))
        .expect("failed to bind");
    socket.set_timeout(Some(Duration::from_millis(100)));
    // Nothing was sent, so the receive times out.
    let err = socket
        .rcv_from()
        .expect_err("expected a timeout with nothing sent");
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "got: {}", err);
}

#[test]
#[ignore]
fn dgram_identifier_after_send_without_bind() {
    let localhost = Ipv4Addr::new(127, 0, 0, 1);
    let mut socket = match DgramIcmpSocket4::new() {
        Ok(s) => s,
        Err(e) => panic!("could not open an ICMP datagram socket ({})", e),
    };
    socket.set_timeout(Some(Duration::from_secs(2)));
    // No bind: on Linux the kernel binds the socket on this send and puts
    // the new local port into the packet's identifier.
    socket
        .send(localhost, 4, vec![0x20; 16])
        .expect("failed to send");
    loop {
        let (resp, _) = socket.rcv_from().expect("failed to receive a reply");
        if let Icmpv4Message::EchoReply {
            identifier,
            sequence: 4,
            ..
        } = resp.message
        {
            assert_eq!(identifier, socket.identifier());
            return;
        }
    }
}
