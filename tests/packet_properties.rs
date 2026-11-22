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
//! Property tests for message parsing, serialization and checksums.
use std::net::Ipv6Addr;

use icmp_socket::options::{
    ExtensionObjectFormat, NdOptionFormat, OptionFormat, Options, OptionsBuilder, RplOptionFormat,
};
use icmp_socket::{Icmpv4Message, Icmpv6Message};
use proptest::prelude::*;

fn ipv6_addr() -> impl Strategy<Value = Ipv6Addr> {
    any::<[u8; 16]>().prop_map(Ipv6Addr::from)
}

fn message_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..160)
}

/// Bytes equal except for the checksum field.
fn same_but_checksum(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a[..2] == b[..2] && a[4..] == b[4..]
}

/// If every option in `bytes` decodes, building the options again gives the
/// same bytes. Reading never panics.
fn options_round_trip<F: OptionFormat>(bytes: &[u8]) -> Result<(), TestCaseError> {
    let decoded: Result<Vec<_>, _> = Options::<F>::new(bytes).collect();
    if let Ok(opts) = decoded {
        let mut builder = OptionsBuilder::<F>::new();
        for opt in opts {
            builder = builder.option(opt.kind, opt.data).unwrap();
        }
        prop_assert_eq!(builder.build(), bytes.to_vec());
    }
    Ok(())
}

proptest! {
    #[test]
    fn option_lists_round_trip(bytes in prop::collection::vec(any::<u8>(), 0..96)) {
        options_round_trip::<NdOptionFormat>(&bytes)?;
        options_round_trip::<ExtensionObjectFormat>(&bytes)?;
        options_round_trip::<RplOptionFormat>(&bytes)?;
    }

    #[test]
    fn v4_parse_never_panics_and_round_trips(bytes in message_bytes()) {
        if let Ok(msg) = Icmpv4Message::parse(&bytes) {
            let again = msg.to_bytes();
            prop_assert!(same_but_checksum(&again, &bytes));
            prop_assert!(Icmpv4Message::verify_checksum(&again));
            prop_assert_eq!(Icmpv4Message::parse(&again).unwrap(), msg);
        }
        Icmpv4Message::verify_checksum(&bytes);
    }

    #[test]
    fn v6_parse_never_panics_and_round_trips(
        bytes in message_bytes(),
        src in ipv6_addr(),
        dst in ipv6_addr(),
    ) {
        if let Ok(msg) = Icmpv6Message::parse(&bytes) {
            let again = msg.to_bytes(&src, &dst);
            prop_assert!(same_but_checksum(&again, &bytes));
            prop_assert!(Icmpv6Message::verify_checksum(&again, &src, &dst));
            prop_assert_eq!(Icmpv6Message::parse(&again).unwrap(), msg.clone());
            prop_assert!(same_but_checksum(&msg.to_bytes_unchecksummed(), &bytes));
        }
        Icmpv6Message::verify_checksum(&bytes, &src, &dst);
    }

    #[test]
    fn v4_corrupted_checksum_fails(bytes in message_bytes(), flip in 0usize..160) {
        if let Ok(msg) = Icmpv4Message::parse(&bytes) {
            let mut wire = msg.to_bytes();
            let i = flip % wire.len();
            wire[i] ^= 0x01;
            prop_assert!(!Icmpv4Message::verify_checksum(&wire));
        }
    }
}
