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
//! Property tests for packet parsing, serialization and checksums.
use std::net::Ipv6Addr;

use icmp_socket::{Icmpv4Packet, Icmpv6Packet};
use proptest::prelude::*;

/// ICMPv4 types the parser decodes.
const V4_TYPES: &[u8] = &[0, 3, 4, 5, 8, 11, 12, 13, 14, 15, 16];
/// ICMPv6 types the parser decodes.
const V6_TYPES: &[u8] = &[1, 2, 3, 4, 100, 101, 128, 129, 200, 201];

/// Bytes that begin with a type the parser decodes.
fn message_bytes(types: &'static [u8]) -> impl Strategy<Value = Vec<u8>> {
    (
        prop::sample::select(types),
        prop::collection::vec(any::<u8>(), 7..120),
    )
        .prop_map(|(typ, rest)| {
            let mut bytes = vec![typ];
            bytes.extend(rest);
            bytes
        })
}

fn ipv6_addr() -> impl Strategy<Value = Ipv6Addr> {
    any::<[u16; 8]>().prop_map(|s| Ipv6Addr::new(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]))
}

/// Timestamp and Information messages keep no bytes after their fixed
/// fields, so they serialize back exactly only at their fixed length.
fn v4_round_trips_exactly(bytes: &[u8]) -> bool {
    match bytes[0] {
        13 | 14 => bytes.len() == 20,
        15 | 16 => bytes.len() == 8,
        _ => true,
    }
}

/// Timestamp messages need 20 bytes; every other decoded type needs 8.
fn v4_long_enough(bytes: &[u8]) -> bool {
    !matches!(bytes[0], 13 | 14) || bytes.len() >= 20
}

proptest! {
    #[test]
    fn v4_parsing_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..120)) {
        for parsed in [
            Icmpv4Packet::parse(&bytes),
            Icmpv4Packet::parse_dgram(&bytes),
            Icmpv4Packet::parse_auto(&bytes),
        ] {
            if let Ok(pkt) = parsed {
                pkt.verify_checksum();
                pkt.get_bytes(true);
            }
        }
        Icmpv4Packet::verify_checksum_bytes(&bytes);
    }

    #[test]
    fn v6_parsing_never_panics(
        bytes in prop::collection::vec(any::<u8>(), 0..120),
        src in ipv6_addr(),
        dst in ipv6_addr(),
    ) {
        if let Ok(pkt) = Icmpv6Packet::parse(&bytes) {
            pkt.verify_checksum(&src, &dst);
            pkt.get_bytes(true);
        }
        Icmpv6Packet::verify_checksum_bytes(&bytes, &src, &dst);
    }

    #[test]
    fn v4_bytes_round_trip(bytes in message_bytes(V4_TYPES)) {
        prop_assume!(v4_long_enough(&bytes));
        let pkt = Icmpv4Packet::parse_dgram(&bytes).unwrap();
        if v4_round_trips_exactly(&bytes) {
            prop_assert_eq!(pkt.get_bytes(true), bytes);
        }
    }

    #[test]
    fn v4_packet_round_trip(bytes in message_bytes(V4_TYPES)) {
        prop_assume!(v4_long_enough(&bytes));
        let pkt = Icmpv4Packet::parse_dgram(&bytes).unwrap();
        let again = Icmpv4Packet::parse_dgram(pkt.get_bytes(true)).unwrap();
        prop_assert_eq!(again, pkt);
    }

    #[test]
    fn v6_bytes_round_trip(bytes in message_bytes(V6_TYPES)) {
        let pkt = Icmpv6Packet::parse(&bytes).unwrap();
        prop_assert_eq!(pkt.get_bytes(true), bytes);
    }

    #[test]
    fn v4_checksum_verifies(bytes in message_bytes(V4_TYPES)) {
        prop_assume!(v4_long_enough(&bytes));
        let pkt = Icmpv4Packet::parse_dgram(&bytes).unwrap().with_checksum();
        prop_assert!(pkt.verify_checksum());
        prop_assert!(Icmpv4Packet::verify_checksum_bytes(&pkt.get_bytes(true)));
    }

    #[test]
    fn v6_checksum_verifies(
        bytes in message_bytes(V6_TYPES),
        src in ipv6_addr(),
        dst in ipv6_addr(),
    ) {
        let pkt = Icmpv6Packet::parse(&bytes).unwrap().with_checksum(&src, &dst);
        prop_assert!(pkt.verify_checksum(&src, &dst));
        prop_assert!(Icmpv6Packet::verify_checksum_bytes(&pkt.get_bytes(true), &src, &dst));
    }
}
