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
//! ICMPv6 messages.
//!
//! [`Icmpv6Message`] has a variant for every type in the IANA "ICMPv6
//! Parameters" type registry; other numbers, including the private
//! experimentation types 100, 101, 200 and 201, parse as
//! [`Icmpv6Message::Other`]. A message is one ICMPv6 message without its
//! IPv6 header.
//!
//! Neighbor Discovery and related messages keep their option lists as bytes
//! (`options`); read them with [`crate::options::Options`] and
//! [`crate::options::NdOptionFormat`]. Lists of records are kept as bytes too,
//! with accessor methods.
//!
//! The ICMPv6 checksum covers a pseudo-header with the source and
//! destination addresses, so the checksummed forms take both addresses. A
//! socket sends with [`Icmpv6Message::to_bytes_unchecksummed`]: the kernel
//! fills the checksum in (RFC 3542 section 3.1).
use std::net::Ipv6Addr;

use crate::checksum;
use crate::error::{ModelledTypeError, ParseError};
use crate::wire::{Reader, Writer, check_header};

pub use crate::icmpv4::extended_echo_flags;

/// ICMPv6 type numbers.
pub mod msg_type {
    pub const DESTINATION_UNREACHABLE: u8 = 1;
    pub const PACKET_TOO_BIG: u8 = 2;
    pub const TIME_EXCEEDED: u8 = 3;
    pub const PARAMETER_PROBLEM: u8 = 4;
    pub const ECHO_REQUEST: u8 = 128;
    pub const ECHO_REPLY: u8 = 129;
    pub const MULTICAST_LISTENER_QUERY: u8 = 130;
    pub const MULTICAST_LISTENER_REPORT: u8 = 131;
    pub const MULTICAST_LISTENER_DONE: u8 = 132;
    pub const ROUTER_SOLICITATION: u8 = 133;
    pub const ROUTER_ADVERTISEMENT: u8 = 134;
    pub const NEIGHBOR_SOLICITATION: u8 = 135;
    pub const NEIGHBOR_ADVERTISEMENT: u8 = 136;
    pub const REDIRECT: u8 = 137;
    pub const ROUTER_RENUMBERING: u8 = 138;
    pub const NODE_INFORMATION_QUERY: u8 = 139;
    pub const NODE_INFORMATION_RESPONSE: u8 = 140;
    pub const INVERSE_NEIGHBOR_SOLICITATION: u8 = 141;
    pub const INVERSE_NEIGHBOR_ADVERTISEMENT: u8 = 142;
    pub const MULTICAST_LISTENER_REPORT_V2: u8 = 143;
    pub const HOME_AGENT_ADDRESS_DISCOVERY_REQUEST: u8 = 144;
    pub const HOME_AGENT_ADDRESS_DISCOVERY_REPLY: u8 = 145;
    pub const MOBILE_PREFIX_SOLICITATION: u8 = 146;
    pub const MOBILE_PREFIX_ADVERTISEMENT: u8 = 147;
    pub const CERTIFICATION_PATH_SOLICITATION: u8 = 148;
    pub const CERTIFICATION_PATH_ADVERTISEMENT: u8 = 149;
    pub const EXPERIMENTAL_MOBILITY: u8 = 150;
    pub const MULTICAST_ROUTER_ADVERTISEMENT: u8 = 151;
    pub const MULTICAST_ROUTER_SOLICITATION: u8 = 152;
    pub const MULTICAST_ROUTER_TERMINATION: u8 = 153;
    pub const FMIPV6: u8 = 154;
    pub const RPL_CONTROL: u8 = 155;
    pub const ILNPV6_LOCATOR_UPDATE: u8 = 156;
    pub const DUPLICATE_ADDRESS_REQUEST: u8 = 157;
    pub const DUPLICATE_ADDRESS_CONFIRMATION: u8 = 158;
    pub const MPL_CONTROL: u8 = 159;
    pub const EXTENDED_ECHO_REQUEST: u8 = 160;
    pub const EXTENDED_ECHO_REPLY: u8 = 161;
}

/// Destination Unreachable codes (RFC 4443, RFC 6554, RFC 8883, RFC 9914).
pub mod unreachable_code {
    pub const NO_ROUTE: u8 = 0;
    pub const ADMINISTRATIVELY_PROHIBITED: u8 = 1;
    pub const BEYOND_SCOPE_OF_SOURCE: u8 = 2;
    pub const ADDRESS: u8 = 3;
    pub const PORT: u8 = 4;
    pub const SOURCE_ADDRESS_FAILED_POLICY: u8 = 5;
    pub const REJECT_ROUTE: u8 = 6;
    pub const SOURCE_ROUTING_HEADER_ERROR: u8 = 7;
    pub const HEADERS_TOO_LONG: u8 = 8;
    pub const P_ROUTE_ERROR: u8 = 9;
}

/// Time Exceeded codes (RFC 4443).
pub mod time_exceeded_code {
    pub const HOP_LIMIT: u8 = 0;
    pub const FRAGMENT_REASSEMBLY: u8 = 1;
}

/// Parameter Problem codes (RFC 4443, RFC 7112, RFC 8754, RFC 8883).
pub mod parameter_problem_code {
    pub const ERRONEOUS_HEADER_FIELD: u8 = 0;
    pub const UNRECOGNIZED_NEXT_HEADER: u8 = 1;
    pub const UNRECOGNIZED_OPTION: u8 = 2;
    pub const INCOMPLETE_HEADER_CHAIN: u8 = 3;
    pub const SR_UPPER_LAYER_HEADER_ERROR: u8 = 4;
    pub const UNRECOGNIZED_NEXT_HEADER_BY_INTERMEDIATE_NODE: u8 = 5;
    pub const EXTENSION_HEADER_TOO_BIG: u8 = 6;
    pub const EXTENSION_HEADER_CHAIN_TOO_LONG: u8 = 7;
    pub const TOO_MANY_EXTENSION_HEADERS: u8 = 8;
    pub const TOO_MANY_OPTIONS: u8 = 9;
    pub const OPTION_TOO_BIG: u8 = 10;
}

/// Router Renumbering codes (RFC 2894).
pub mod router_renumbering_code {
    pub const COMMAND: u8 = 0;
    pub const RESULT: u8 = 1;
    pub const SEQUENCE_NUMBER_RESET: u8 = 255;
}

/// Node Information Query codes (RFC 4620).
pub mod node_information_query_code {
    pub const IPV6_SUBJECT: u8 = 0;
    pub const NAME_SUBJECT: u8 = 1;
    pub const IPV4_SUBJECT: u8 = 2;
}

/// Node Information Response codes (RFC 4620).
pub mod node_information_response_code {
    pub const SUCCESS: u8 = 0;
    pub const REFUSED: u8 = 1;
    pub const UNKNOWN_QTYPE: u8 = 2;
}

/// RPL Control Message codes (RFC 6550, RFC 6997, RFC 6998, RFC 9009, RFC
/// 9914). [`SECURE`](rpl_code::SECURE) marks the secure variant.
pub mod rpl_code {
    pub const DIS: u8 = 0x00;
    pub const DIO: u8 = 0x01;
    pub const DAO: u8 = 0x02;
    pub const DAO_ACK: u8 = 0x03;
    pub const P2P_DRO: u8 = 0x04;
    pub const P2P_DRO_ACK: u8 = 0x05;
    pub const MEASUREMENT_OBJECT: u8 = 0x06;
    pub const DCO: u8 = 0x07;
    pub const DCO_ACK: u8 = 0x08;
    pub const P_DAO_REQUEST: u8 = 0x09;
    pub const PDR_ACK: u8 = 0x0A;
    pub const CONSISTENCY_CHECK: u8 = 0x8A;
    /// The bit that marks a secure RPL message.
    pub const SECURE: u8 = 0x80;
}

/// Extended Echo Reply codes (RFC 8335).
pub use crate::icmpv4::extended_echo_reply_code;

/// Router Advertisement flag bits (IANA "IPv6 ND Router Advertisement
/// Flags").
pub mod router_advertisement_flags {
    pub const MANAGED: u8 = 0x80;
    pub const OTHER: u8 = 0x40;
    pub const HOME_AGENT: u8 = 0x20;
    /// The two-bit router preference (RFC 4191).
    pub const PREFERENCE_MASK: u8 = 0x18;
    pub const PROXY: u8 = 0x04;
    pub const SNAC_ROUTER: u8 = 0x02;
}

/// Neighbor Advertisement flag bits (RFC 4861).
pub mod neighbor_advertisement_flags {
    pub const ROUTER: u32 = 0x8000_0000;
    pub const SOLICITED: u32 = 0x4000_0000;
    pub const OVERRIDE: u32 = 0x2000_0000;
}

/// An ICMPv6 message. The variant is the message type; [`Self::typ`]
/// returns its number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Icmpv6Message {
    /// Type 1 (RFC 4443). `rest` holds bytes 4..8; see
    /// [`Icmpv6Message::extensions`]. `original` is the start of the packet
    /// that caused the error (plus any RFC 4884 extensions).
    DestinationUnreachable {
        code: u8,
        rest: [u8; 4],
        original: Vec<u8>,
    },
    /// Type 2 (RFC 4443).
    PacketTooBig {
        code: u8,
        mtu: u32,
        original: Vec<u8>,
    },
    /// Type 3 (RFC 4443). `rest` holds bytes 4..8; see
    /// [`Icmpv6Message::extensions`].
    TimeExceeded {
        code: u8,
        rest: [u8; 4],
        original: Vec<u8>,
    },
    /// Type 4 (RFC 4443). `pointer` is the offset of the error.
    ParameterProblem {
        code: u8,
        pointer: u32,
        original: Vec<u8>,
    },
    /// Type 128 (RFC 4443).
    EchoRequest {
        code: u8,
        identifier: u16,
        sequence: u16,
        payload: Vec<u8>,
    },
    /// Type 129 (RFC 4443).
    EchoReply {
        code: u8,
        identifier: u16,
        sequence: u16,
        payload: Vec<u8>,
    },
    /// Type 130 (RFC 2710, RFC 9777). A 24-byte message is an MLDv1 query
    /// and `v2` is empty; an MLDv2 query has the bytes from offset 24 (flags,
    /// QQIC, source count and sources) in `v2`. Other lengths are invalid.
    MulticastListenerQuery {
        code: u8,
        maximum_response: u16,
        reserved: u16,
        multicast_address: Ipv6Addr,
        v2: Vec<u8>,
    },
    /// Type 131 (RFC 2710). RFC 2710 tells receivers to ignore bytes after
    /// the first 24; they are kept in `trailing`.
    MulticastListenerReport {
        code: u8,
        maximum_response: u16,
        reserved: u16,
        multicast_address: Ipv6Addr,
        trailing: Vec<u8>,
    },
    /// Type 132 (RFC 2710). See `MulticastListenerReport` for `trailing`.
    MulticastListenerDone {
        code: u8,
        maximum_response: u16,
        reserved: u16,
        multicast_address: Ipv6Addr,
        trailing: Vec<u8>,
    },
    /// Type 133 (RFC 4861).
    RouterSolicitation {
        code: u8,
        reserved: [u8; 4],
        options: Vec<u8>,
    },
    /// Type 134 (RFC 4861). See [`router_advertisement_flags`].
    RouterAdvertisement {
        code: u8,
        cur_hop_limit: u8,
        flags: u8,
        router_lifetime: u16,
        reachable_time: u32,
        retrans_timer: u32,
        options: Vec<u8>,
    },
    /// Type 135 (RFC 4861).
    NeighborSolicitation {
        code: u8,
        reserved: [u8; 4],
        target: Ipv6Addr,
        options: Vec<u8>,
    },
    /// Type 136 (RFC 4861). `flags` holds the R, S and O bits and 29
    /// reserved bits; see [`neighbor_advertisement_flags`].
    NeighborAdvertisement {
        code: u8,
        flags: u32,
        target: Ipv6Addr,
        options: Vec<u8>,
    },
    /// Type 137 (RFC 4861).
    Redirect {
        code: u8,
        reserved: [u8; 4],
        target: Ipv6Addr,
        destination: Ipv6Addr,
        options: Vec<u8>,
    },
    /// Type 138 (RFC 2894). `body` depends on the code (see
    /// [`router_renumbering_code`]).
    RouterRenumbering {
        code: u8,
        sequence_number: u32,
        segment_number: u8,
        flags: u8,
        max_delay: u16,
        reserved: u32,
        body: Vec<u8>,
    },
    /// Type 139 (RFC 4620).
    NodeInformationQuery {
        code: u8,
        qtype: u16,
        flags: u16,
        nonce: [u8; 8],
        data: Vec<u8>,
    },
    /// Type 140 (RFC 4620).
    NodeInformationResponse {
        code: u8,
        qtype: u16,
        flags: u16,
        nonce: [u8; 8],
        data: Vec<u8>,
    },
    /// Type 141 (RFC 3122).
    InverseNeighborSolicitation {
        code: u8,
        reserved: [u8; 4],
        options: Vec<u8>,
    },
    /// Type 142 (RFC 3122).
    InverseNeighborAdvertisement {
        code: u8,
        reserved: [u8; 4],
        options: Vec<u8>,
    },
    /// Type 143 (RFC 9777). `records` holds the multicast address records
    /// (and any bytes after them); `record_count` is the message's count.
    MulticastListenerReportV2 {
        code: u8,
        flags: u16,
        record_count: u16,
        records: Vec<u8>,
    },
    /// Type 144 (RFC 6275). Exactly 8 bytes.
    HomeAgentAddressDiscoveryRequest {
        code: u8,
        identifier: u16,
        reserved: u16,
    },
    /// Type 145 (RFC 6275). See [`Icmpv6Message::home_agent_addresses`].
    HomeAgentAddressDiscoveryReply {
        code: u8,
        identifier: u16,
        reserved: u16,
        addresses: Vec<u8>,
    },
    /// Type 146 (RFC 6275).
    MobilePrefixSolicitation {
        code: u8,
        identifier: u16,
        reserved: u16,
        options: Vec<u8>,
    },
    /// Type 147 (RFC 6275). `flags` holds the M and O bits.
    MobilePrefixAdvertisement {
        code: u8,
        identifier: u16,
        flags: u16,
        options: Vec<u8>,
    },
    /// Type 148 (RFC 3971).
    CertificationPathSolicitation {
        code: u8,
        identifier: u16,
        component: u16,
        options: Vec<u8>,
    },
    /// Type 149 (RFC 3971).
    CertificationPathAdvertisement {
        code: u8,
        identifier: u16,
        all_components: u16,
        component: u16,
        reserved: u16,
        options: Vec<u8>,
    },
    /// Type 150 (RFC 4065): messages of experimental mobility protocols
    /// such as Seamoby.
    ExperimentalMobility {
        code: u8,
        subtype: u8,
        reserved: [u8; 3],
        body: Vec<u8>,
    },
    /// Type 151 (RFC 4286). Exactly 8 bytes. The advertisement interval is
    /// in the code position; [`Icmpv6Message::code`] returns it.
    MulticastRouterAdvertisement {
        advertisement_interval: u8,
        query_interval: u16,
        robustness_variable: u16,
    },
    /// Type 152 (RFC 4286). Exactly 4 bytes; `reserved` is in the code
    /// position.
    MulticastRouterSolicitation { reserved: u8 },
    /// Type 153 (RFC 4286). Exactly 4 bytes; `reserved` is in the code
    /// position.
    MulticastRouterTermination { reserved: u8 },
    /// Type 154 (RFC 5568).
    Fmipv6 {
        code: u8,
        subtype: u8,
        reserved: u8,
        identifier: u16,
        options: Vec<u8>,
    },
    /// Type 155 (RFC 6550). There is no fixed field after the checksum:
    /// `body` holds the security section (for secure codes), the base
    /// object and the RPL options (read them with
    /// [`crate::options::RplOptionFormat`]).
    RplControl { code: u8, body: Vec<u8> },
    /// Type 156 (RFC 6743). `locators` holds the 12-byte locator entries.
    Ilnpv6LocatorUpdate {
        code: u8,
        num_locators: u8,
        operation: u8,
        reserved: u16,
        locators: Vec<u8>,
    },
    /// Type 157 (RFC 6775, RFC 8505). The low 4 bits of the code give the
    /// size of `rovr` (the EUI-64 or ROVR field).
    DuplicateAddressRequest {
        code: u8,
        status: u8,
        tid: u8,
        registration_lifetime: u16,
        rovr: Vec<u8>,
        registered_address: Ipv6Addr,
    },
    /// Type 158 (RFC 6775, RFC 8505).
    DuplicateAddressConfirmation {
        code: u8,
        status: u8,
        tid: u8,
        registration_lifetime: u16,
        rovr: Vec<u8>,
        registered_address: Ipv6Addr,
    },
    /// Type 159 (RFC 7731). There is no fixed field after the checksum;
    /// `seed_info` holds the MPL Seed Info entries.
    MplControl { code: u8, seed_info: Vec<u8> },
    /// Type 160 (RFC 8335). The sequence number has 8 bits; see
    /// [`extended_echo_flags`].
    ExtendedEchoRequest {
        code: u8,
        identifier: u16,
        sequence: u8,
        flags: u8,
        extensions: Vec<u8>,
    },
    /// Type 161 (RFC 8335).
    ExtendedEchoReply {
        code: u8,
        identifier: u16,
        sequence: u8,
        flags: u8,
        extensions: Vec<u8>,
    },
    /// A type this crate does not model: unassigned, reserved and private
    /// experimentation numbers.
    Other(Icmpv6Other),
}

/// An ICMPv6 message of a type that has no variant of its own: its type,
/// code and the bytes after the checksum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmpv6Other {
    typ: u8,
    code: u8,
    body: Vec<u8>,
}

impl Icmpv6Other {
    /// Build an `Other` message. Fails for a type that has its own variant,
    /// so an `Other` never holds a modelled type.
    pub fn new(typ: u8, code: u8, body: Vec<u8>) -> Result<Self, ModelledTypeError> {
        if is_modelled(typ) {
            return Err(ModelledTypeError { typ });
        }
        Ok(Self { typ, code, body })
    }

    pub fn typ(&self) -> u8 {
        self.typ
    }

    pub fn code(&self) -> u8 {
        self.code
    }

    /// The bytes after the checksum field.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

fn is_modelled(typ: u8) -> bool {
    matches!(typ, 1..=4 | 128..=161)
}

impl Icmpv6Message {
    /// An echo request with code 0.
    pub fn echo_request(identifier: u16, sequence: u16, payload: Vec<u8>) -> Self {
        Self::EchoRequest {
            code: 0,
            identifier,
            sequence,
            payload,
        }
    }

    /// An echo reply with code 0.
    pub fn echo_reply(identifier: u16, sequence: u16, payload: Vec<u8>) -> Self {
        Self::EchoReply {
            code: 0,
            identifier,
            sequence,
            payload,
        }
    }

    /// The type number.
    pub fn typ(&self) -> u8 {
        use msg_type::*;
        match self {
            Self::DestinationUnreachable { .. } => DESTINATION_UNREACHABLE,
            Self::PacketTooBig { .. } => PACKET_TOO_BIG,
            Self::TimeExceeded { .. } => TIME_EXCEEDED,
            Self::ParameterProblem { .. } => PARAMETER_PROBLEM,
            Self::EchoRequest { .. } => ECHO_REQUEST,
            Self::EchoReply { .. } => ECHO_REPLY,
            Self::MulticastListenerQuery { .. } => MULTICAST_LISTENER_QUERY,
            Self::MulticastListenerReport { .. } => MULTICAST_LISTENER_REPORT,
            Self::MulticastListenerDone { .. } => MULTICAST_LISTENER_DONE,
            Self::RouterSolicitation { .. } => ROUTER_SOLICITATION,
            Self::RouterAdvertisement { .. } => ROUTER_ADVERTISEMENT,
            Self::NeighborSolicitation { .. } => NEIGHBOR_SOLICITATION,
            Self::NeighborAdvertisement { .. } => NEIGHBOR_ADVERTISEMENT,
            Self::Redirect { .. } => REDIRECT,
            Self::RouterRenumbering { .. } => ROUTER_RENUMBERING,
            Self::NodeInformationQuery { .. } => NODE_INFORMATION_QUERY,
            Self::NodeInformationResponse { .. } => NODE_INFORMATION_RESPONSE,
            Self::InverseNeighborSolicitation { .. } => INVERSE_NEIGHBOR_SOLICITATION,
            Self::InverseNeighborAdvertisement { .. } => INVERSE_NEIGHBOR_ADVERTISEMENT,
            Self::MulticastListenerReportV2 { .. } => MULTICAST_LISTENER_REPORT_V2,
            Self::HomeAgentAddressDiscoveryRequest { .. } => HOME_AGENT_ADDRESS_DISCOVERY_REQUEST,
            Self::HomeAgentAddressDiscoveryReply { .. } => HOME_AGENT_ADDRESS_DISCOVERY_REPLY,
            Self::MobilePrefixSolicitation { .. } => MOBILE_PREFIX_SOLICITATION,
            Self::MobilePrefixAdvertisement { .. } => MOBILE_PREFIX_ADVERTISEMENT,
            Self::CertificationPathSolicitation { .. } => CERTIFICATION_PATH_SOLICITATION,
            Self::CertificationPathAdvertisement { .. } => CERTIFICATION_PATH_ADVERTISEMENT,
            Self::ExperimentalMobility { .. } => EXPERIMENTAL_MOBILITY,
            Self::MulticastRouterAdvertisement { .. } => MULTICAST_ROUTER_ADVERTISEMENT,
            Self::MulticastRouterSolicitation { .. } => MULTICAST_ROUTER_SOLICITATION,
            Self::MulticastRouterTermination { .. } => MULTICAST_ROUTER_TERMINATION,
            Self::Fmipv6 { .. } => FMIPV6,
            Self::RplControl { .. } => RPL_CONTROL,
            Self::Ilnpv6LocatorUpdate { .. } => ILNPV6_LOCATOR_UPDATE,
            Self::DuplicateAddressRequest { .. } => DUPLICATE_ADDRESS_REQUEST,
            Self::DuplicateAddressConfirmation { .. } => DUPLICATE_ADDRESS_CONFIRMATION,
            Self::MplControl { .. } => MPL_CONTROL,
            Self::ExtendedEchoRequest { .. } => EXTENDED_ECHO_REQUEST,
            Self::ExtendedEchoReply { .. } => EXTENDED_ECHO_REPLY,
            Self::Other(o) => o.typ,
        }
    }

    /// The code: byte 1 of the message. For types 151 to 153 that byte is
    /// not a code; this returns it anyway.
    pub fn code(&self) -> u8 {
        match self {
            Self::DestinationUnreachable { code, .. }
            | Self::PacketTooBig { code, .. }
            | Self::TimeExceeded { code, .. }
            | Self::ParameterProblem { code, .. }
            | Self::EchoRequest { code, .. }
            | Self::EchoReply { code, .. }
            | Self::MulticastListenerQuery { code, .. }
            | Self::MulticastListenerReport { code, .. }
            | Self::MulticastListenerDone { code, .. }
            | Self::RouterSolicitation { code, .. }
            | Self::RouterAdvertisement { code, .. }
            | Self::NeighborSolicitation { code, .. }
            | Self::NeighborAdvertisement { code, .. }
            | Self::Redirect { code, .. }
            | Self::RouterRenumbering { code, .. }
            | Self::NodeInformationQuery { code, .. }
            | Self::NodeInformationResponse { code, .. }
            | Self::InverseNeighborSolicitation { code, .. }
            | Self::InverseNeighborAdvertisement { code, .. }
            | Self::MulticastListenerReportV2 { code, .. }
            | Self::HomeAgentAddressDiscoveryRequest { code, .. }
            | Self::HomeAgentAddressDiscoveryReply { code, .. }
            | Self::MobilePrefixSolicitation { code, .. }
            | Self::MobilePrefixAdvertisement { code, .. }
            | Self::CertificationPathSolicitation { code, .. }
            | Self::CertificationPathAdvertisement { code, .. }
            | Self::ExperimentalMobility { code, .. }
            | Self::Fmipv6 { code, .. }
            | Self::RplControl { code, .. }
            | Self::Ilnpv6LocatorUpdate { code, .. }
            | Self::DuplicateAddressRequest { code, .. }
            | Self::DuplicateAddressConfirmation { code, .. }
            | Self::MplControl { code, .. }
            | Self::ExtendedEchoRequest { code, .. }
            | Self::ExtendedEchoReply { code, .. } => *code,
            Self::MulticastRouterAdvertisement {
                advertisement_interval,
                ..
            } => *advertisement_interval,
            Self::MulticastRouterSolicitation { reserved }
            | Self::MulticastRouterTermination { reserved } => *reserved,
            Self::Other(o) => o.code,
        }
    }

    /// The length in bytes of the original packet when the message carries
    /// RFC 4884 extensions after it, or `None` when the length field is 0
    /// (no extensions) or the type has no such field.
    pub fn extension_length(&self) -> Option<usize> {
        match self {
            Self::DestinationUnreachable { rest, .. } | Self::TimeExceeded { rest, .. } => {
                // ICMPv6 counts the length in 64-bit words (RFC 4884).
                (rest[0] != 0).then_some(usize::from(rest[0]) * 8)
            }
            _ => None,
        }
    }

    /// The RFC 4884 extension structure the message carries, if any; read
    /// it with [`crate::options::ExtensionHeader::split`].
    pub fn extensions(&self) -> Option<&[u8]> {
        match self {
            Self::DestinationUnreachable { original, .. } | Self::TimeExceeded { original, .. } => {
                let len = self.extension_length()?;
                original.get(len..).filter(|e| !e.is_empty())
            }
            Self::ExtendedEchoRequest { extensions, .. }
            | Self::ExtendedEchoReply { extensions, .. } => {
                (!extensions.is_empty()).then_some(extensions.as_slice())
            }
            _ => None,
        }
    }

    /// The Neighbor Discovery option list of a message that has one, for
    /// [`crate::options::Options`] with [`crate::options::NdOptionFormat`].
    pub fn nd_options(&self) -> Option<&[u8]> {
        match self {
            Self::RouterSolicitation { options, .. }
            | Self::RouterAdvertisement { options, .. }
            | Self::NeighborSolicitation { options, .. }
            | Self::NeighborAdvertisement { options, .. }
            | Self::Redirect { options, .. }
            | Self::InverseNeighborSolicitation { options, .. }
            | Self::InverseNeighborAdvertisement { options, .. }
            | Self::MobilePrefixSolicitation { options, .. }
            | Self::MobilePrefixAdvertisement { options, .. }
            | Self::CertificationPathSolicitation { options, .. }
            | Self::CertificationPathAdvertisement { options, .. }
            | Self::Fmipv6 { options, .. } => Some(options),
            _ => None,
        }
    }

    /// The home agent addresses of a Home Agent Address Discovery Reply, or
    /// `None` for any other message. Bytes after the last whole address are
    /// ignored.
    pub fn home_agent_addresses(&self) -> Option<Vec<Ipv6Addr>> {
        let Self::HomeAgentAddressDiscoveryReply { addresses, .. } = self else {
            return None;
        };
        Some(
            addresses
                .chunks_exact(16)
                .map(|a| {
                    let mut octets = [0; 16];
                    octets.copy_from_slice(a);
                    Ipv6Addr::from(octets)
                })
                .collect(),
        )
    }

    /// Parse one ICMPv6 message. `bytes` begins at the type field. The
    /// checksum is not checked; see [`Self::verify_checksum`].
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        use msg_type::*;
        check_header(bytes)?;
        let (typ, code) = (bytes[0], bytes[1]);
        let mut r = Reader::after_header(bytes);
        Ok(match typ {
            DESTINATION_UNREACHABLE | TIME_EXCEEDED => {
                r.need(8)?;
                let (rest, original) = (r.array()?, r.rest());
                if typ == DESTINATION_UNREACHABLE {
                    Self::DestinationUnreachable {
                        code,
                        rest,
                        original,
                    }
                } else {
                    Self::TimeExceeded {
                        code,
                        rest,
                        original,
                    }
                }
            }
            PACKET_TOO_BIG => {
                r.need(8)?;
                Self::PacketTooBig {
                    code,
                    mtu: r.u32()?,
                    original: r.rest(),
                }
            }
            PARAMETER_PROBLEM => {
                r.need(8)?;
                Self::ParameterProblem {
                    code,
                    pointer: r.u32()?,
                    original: r.rest(),
                }
            }
            ECHO_REQUEST | ECHO_REPLY => {
                r.need(8)?;
                let (identifier, sequence, payload) = (r.u16()?, r.u16()?, r.rest());
                if typ == ECHO_REQUEST {
                    Self::EchoRequest {
                        code,
                        identifier,
                        sequence,
                        payload,
                    }
                } else {
                    Self::EchoReply {
                        code,
                        identifier,
                        sequence,
                        payload,
                    }
                }
            }
            MULTICAST_LISTENER_QUERY => {
                // RFC 9777 section 8.1: 24 bytes is MLDv1, 28 or more MLDv2.
                if bytes.len() != 24 {
                    r.need(28)?;
                }
                Self::MulticastListenerQuery {
                    code,
                    maximum_response: r.u16()?,
                    reserved: r.u16()?,
                    multicast_address: r.ipv6()?,
                    v2: r.rest(),
                }
            }
            MULTICAST_LISTENER_REPORT | MULTICAST_LISTENER_DONE => {
                r.need(24)?;
                let (maximum_response, reserved, multicast_address, trailing) =
                    (r.u16()?, r.u16()?, r.ipv6()?, r.rest());
                if typ == MULTICAST_LISTENER_REPORT {
                    Self::MulticastListenerReport {
                        code,
                        maximum_response,
                        reserved,
                        multicast_address,
                        trailing,
                    }
                } else {
                    Self::MulticastListenerDone {
                        code,
                        maximum_response,
                        reserved,
                        multicast_address,
                        trailing,
                    }
                }
            }
            ROUTER_SOLICITATION
            | INVERSE_NEIGHBOR_SOLICITATION
            | INVERSE_NEIGHBOR_ADVERTISEMENT => {
                r.need(8)?;
                let (reserved, options) = (r.array()?, r.rest());
                match typ {
                    ROUTER_SOLICITATION => Self::RouterSolicitation {
                        code,
                        reserved,
                        options,
                    },
                    INVERSE_NEIGHBOR_SOLICITATION => Self::InverseNeighborSolicitation {
                        code,
                        reserved,
                        options,
                    },
                    _ => Self::InverseNeighborAdvertisement {
                        code,
                        reserved,
                        options,
                    },
                }
            }
            ROUTER_ADVERTISEMENT => {
                r.need(16)?;
                Self::RouterAdvertisement {
                    code,
                    cur_hop_limit: r.u8()?,
                    flags: r.u8()?,
                    router_lifetime: r.u16()?,
                    reachable_time: r.u32()?,
                    retrans_timer: r.u32()?,
                    options: r.rest(),
                }
            }
            NEIGHBOR_SOLICITATION => {
                r.need(24)?;
                Self::NeighborSolicitation {
                    code,
                    reserved: r.array()?,
                    target: r.ipv6()?,
                    options: r.rest(),
                }
            }
            NEIGHBOR_ADVERTISEMENT => {
                r.need(24)?;
                Self::NeighborAdvertisement {
                    code,
                    flags: r.u32()?,
                    target: r.ipv6()?,
                    options: r.rest(),
                }
            }
            REDIRECT => {
                r.need(40)?;
                Self::Redirect {
                    code,
                    reserved: r.array()?,
                    target: r.ipv6()?,
                    destination: r.ipv6()?,
                    options: r.rest(),
                }
            }
            ROUTER_RENUMBERING => {
                r.need(16)?;
                Self::RouterRenumbering {
                    code,
                    sequence_number: r.u32()?,
                    segment_number: r.u8()?,
                    flags: r.u8()?,
                    max_delay: r.u16()?,
                    reserved: r.u32()?,
                    body: r.rest(),
                }
            }
            NODE_INFORMATION_QUERY | NODE_INFORMATION_RESPONSE => {
                r.need(16)?;
                let (qtype, flags, nonce, data) = (r.u16()?, r.u16()?, r.array()?, r.rest());
                if typ == NODE_INFORMATION_QUERY {
                    Self::NodeInformationQuery {
                        code,
                        qtype,
                        flags,
                        nonce,
                        data,
                    }
                } else {
                    Self::NodeInformationResponse {
                        code,
                        qtype,
                        flags,
                        nonce,
                        data,
                    }
                }
            }
            MULTICAST_LISTENER_REPORT_V2 => {
                r.need(8)?;
                Self::MulticastListenerReportV2 {
                    code,
                    flags: r.u16()?,
                    record_count: r.u16()?,
                    records: r.rest(),
                }
            }
            HOME_AGENT_ADDRESS_DISCOVERY_REQUEST => {
                r.exactly(8)?;
                Self::HomeAgentAddressDiscoveryRequest {
                    code,
                    identifier: r.u16()?,
                    reserved: r.u16()?,
                }
            }
            HOME_AGENT_ADDRESS_DISCOVERY_REPLY => {
                r.need(8)?;
                Self::HomeAgentAddressDiscoveryReply {
                    code,
                    identifier: r.u16()?,
                    reserved: r.u16()?,
                    addresses: r.rest(),
                }
            }
            MOBILE_PREFIX_SOLICITATION => {
                r.need(8)?;
                Self::MobilePrefixSolicitation {
                    code,
                    identifier: r.u16()?,
                    reserved: r.u16()?,
                    options: r.rest(),
                }
            }
            MOBILE_PREFIX_ADVERTISEMENT => {
                r.need(8)?;
                Self::MobilePrefixAdvertisement {
                    code,
                    identifier: r.u16()?,
                    flags: r.u16()?,
                    options: r.rest(),
                }
            }
            CERTIFICATION_PATH_SOLICITATION => {
                r.need(8)?;
                Self::CertificationPathSolicitation {
                    code,
                    identifier: r.u16()?,
                    component: r.u16()?,
                    options: r.rest(),
                }
            }
            CERTIFICATION_PATH_ADVERTISEMENT => {
                r.need(12)?;
                Self::CertificationPathAdvertisement {
                    code,
                    identifier: r.u16()?,
                    all_components: r.u16()?,
                    component: r.u16()?,
                    reserved: r.u16()?,
                    options: r.rest(),
                }
            }
            EXPERIMENTAL_MOBILITY => {
                r.need(8)?;
                Self::ExperimentalMobility {
                    code,
                    subtype: r.u8()?,
                    reserved: r.array()?,
                    body: r.rest(),
                }
            }
            MULTICAST_ROUTER_ADVERTISEMENT => {
                r.exactly(8)?;
                Self::MulticastRouterAdvertisement {
                    advertisement_interval: code,
                    query_interval: r.u16()?,
                    robustness_variable: r.u16()?,
                }
            }
            MULTICAST_ROUTER_SOLICITATION => {
                r.exactly(4)?;
                Self::MulticastRouterSolicitation { reserved: code }
            }
            MULTICAST_ROUTER_TERMINATION => {
                r.exactly(4)?;
                Self::MulticastRouterTermination { reserved: code }
            }
            FMIPV6 => {
                r.need(8)?;
                Self::Fmipv6 {
                    code,
                    subtype: r.u8()?,
                    reserved: r.u8()?,
                    identifier: r.u16()?,
                    options: r.rest(),
                }
            }
            RPL_CONTROL => Self::RplControl {
                code,
                body: r.rest(),
            },
            ILNPV6_LOCATOR_UPDATE => {
                r.need(8)?;
                Self::Ilnpv6LocatorUpdate {
                    code,
                    num_locators: r.u8()?,
                    operation: r.u8()?,
                    reserved: r.u16()?,
                    locators: r.rest(),
                }
            }
            DUPLICATE_ADDRESS_REQUEST | DUPLICATE_ADDRESS_CONFIRMATION => {
                // The ROVR fills the space between the fixed fields and the
                // registered address (RFC 8505): 8 to 32 bytes.
                r.need(32)?;
                let (status, tid, registration_lifetime) = (r.u8()?, r.u8()?, r.u16()?);
                let rovr = r.until_last(16);
                let registered_address = r.ipv6()?;
                if typ == DUPLICATE_ADDRESS_REQUEST {
                    Self::DuplicateAddressRequest {
                        code,
                        status,
                        tid,
                        registration_lifetime,
                        rovr,
                        registered_address,
                    }
                } else {
                    Self::DuplicateAddressConfirmation {
                        code,
                        status,
                        tid,
                        registration_lifetime,
                        rovr,
                        registered_address,
                    }
                }
            }
            MPL_CONTROL => Self::MplControl {
                code,
                seed_info: r.rest(),
            },
            EXTENDED_ECHO_REQUEST | EXTENDED_ECHO_REPLY => {
                r.need(8)?;
                let (identifier, sequence, flags) = (r.u16()?, r.u8()?, r.u8()?);
                let extensions = r.rest();
                if typ == EXTENDED_ECHO_REQUEST {
                    Self::ExtendedEchoRequest {
                        code,
                        identifier,
                        sequence,
                        flags,
                        extensions,
                    }
                } else {
                    Self::ExtendedEchoReply {
                        code,
                        identifier,
                        sequence,
                        flags,
                        extensions,
                    }
                }
            }
            _ => Self::Other(Icmpv6Other {
                typ,
                code,
                body: r.rest(),
            }),
        })
    }

    fn write_body(&self, out: &mut Vec<u8>) {
        let mut w = Writer::header(out, self.typ(), self.code());
        match self {
            Self::DestinationUnreachable { rest, original, .. }
            | Self::TimeExceeded { rest, original, .. } => {
                w.bytes(rest).bytes(original);
            }
            Self::PacketTooBig {
                mtu: value,
                original,
                ..
            }
            | Self::ParameterProblem {
                pointer: value,
                original,
                ..
            } => {
                w.u32(*value).bytes(original);
            }
            Self::EchoRequest {
                identifier,
                sequence,
                payload,
                ..
            }
            | Self::EchoReply {
                identifier,
                sequence,
                payload,
                ..
            } => {
                w.u16(*identifier).u16(*sequence).bytes(payload);
            }
            Self::MulticastListenerQuery {
                maximum_response,
                reserved,
                multicast_address,
                v2: rest,
                ..
            }
            | Self::MulticastListenerReport {
                maximum_response,
                reserved,
                multicast_address,
                trailing: rest,
                ..
            }
            | Self::MulticastListenerDone {
                maximum_response,
                reserved,
                multicast_address,
                trailing: rest,
                ..
            } => {
                w.u16(*maximum_response)
                    .u16(*reserved)
                    .ipv6(multicast_address)
                    .bytes(rest);
            }
            Self::RouterSolicitation {
                reserved, options, ..
            }
            | Self::InverseNeighborSolicitation {
                reserved, options, ..
            }
            | Self::InverseNeighborAdvertisement {
                reserved, options, ..
            } => {
                w.bytes(reserved).bytes(options);
            }
            Self::RouterAdvertisement {
                cur_hop_limit,
                flags,
                router_lifetime,
                reachable_time,
                retrans_timer,
                options,
                ..
            } => {
                w.u8(*cur_hop_limit)
                    .u8(*flags)
                    .u16(*router_lifetime)
                    .u32(*reachable_time)
                    .u32(*retrans_timer)
                    .bytes(options);
            }
            Self::NeighborSolicitation {
                reserved,
                target,
                options,
                ..
            } => {
                w.bytes(reserved).ipv6(target).bytes(options);
            }
            Self::NeighborAdvertisement {
                flags,
                target,
                options,
                ..
            } => {
                w.u32(*flags).ipv6(target).bytes(options);
            }
            Self::Redirect {
                reserved,
                target,
                destination,
                options,
                ..
            } => {
                w.bytes(reserved)
                    .ipv6(target)
                    .ipv6(destination)
                    .bytes(options);
            }
            Self::RouterRenumbering {
                sequence_number,
                segment_number,
                flags,
                max_delay,
                reserved,
                body,
                ..
            } => {
                w.u32(*sequence_number)
                    .u8(*segment_number)
                    .u8(*flags)
                    .u16(*max_delay)
                    .u32(*reserved)
                    .bytes(body);
            }
            Self::NodeInformationQuery {
                qtype,
                flags,
                nonce,
                data,
                ..
            }
            | Self::NodeInformationResponse {
                qtype,
                flags,
                nonce,
                data,
                ..
            } => {
                w.u16(*qtype).u16(*flags).bytes(nonce).bytes(data);
            }
            Self::MulticastListenerReportV2 {
                flags,
                record_count,
                records,
                ..
            } => {
                w.u16(*flags).u16(*record_count).bytes(records);
            }
            Self::HomeAgentAddressDiscoveryRequest {
                identifier,
                reserved,
                ..
            } => {
                w.u16(*identifier).u16(*reserved);
            }
            Self::HomeAgentAddressDiscoveryReply {
                identifier,
                reserved: second,
                addresses: rest,
                ..
            }
            | Self::MobilePrefixSolicitation {
                identifier,
                reserved: second,
                options: rest,
                ..
            }
            | Self::MobilePrefixAdvertisement {
                identifier,
                flags: second,
                options: rest,
                ..
            }
            | Self::CertificationPathSolicitation {
                identifier,
                component: second,
                options: rest,
                ..
            } => {
                w.u16(*identifier).u16(*second).bytes(rest);
            }
            Self::CertificationPathAdvertisement {
                identifier,
                all_components,
                component,
                reserved,
                options,
                ..
            } => {
                w.u16(*identifier)
                    .u16(*all_components)
                    .u16(*component)
                    .u16(*reserved)
                    .bytes(options);
            }
            Self::ExperimentalMobility {
                subtype,
                reserved,
                body,
                ..
            } => {
                w.u8(*subtype).bytes(reserved).bytes(body);
            }
            Self::MulticastRouterAdvertisement {
                query_interval,
                robustness_variable,
                ..
            } => {
                w.u16(*query_interval).u16(*robustness_variable);
            }
            Self::MulticastRouterSolicitation { .. } | Self::MulticastRouterTermination { .. } => {}
            Self::Fmipv6 {
                subtype,
                reserved,
                identifier,
                options,
                ..
            } => {
                w.u8(*subtype).u8(*reserved).u16(*identifier).bytes(options);
            }
            Self::RplControl { body, .. }
            | Self::MplControl {
                seed_info: body, ..
            } => {
                w.bytes(body);
            }
            Self::Ilnpv6LocatorUpdate {
                num_locators,
                operation,
                reserved,
                locators,
                ..
            } => {
                w.u8(*num_locators)
                    .u8(*operation)
                    .u16(*reserved)
                    .bytes(locators);
            }
            Self::DuplicateAddressRequest {
                status,
                tid,
                registration_lifetime,
                rovr,
                registered_address,
                ..
            }
            | Self::DuplicateAddressConfirmation {
                status,
                tid,
                registration_lifetime,
                rovr,
                registered_address,
                ..
            } => {
                w.u8(*status)
                    .u8(*tid)
                    .u16(*registration_lifetime)
                    .bytes(rovr)
                    .ipv6(registered_address);
            }
            Self::ExtendedEchoRequest {
                identifier,
                sequence,
                flags,
                extensions,
                ..
            }
            | Self::ExtendedEchoReply {
                identifier,
                sequence,
                flags,
                extensions,
                ..
            } => {
                w.u16(*identifier)
                    .u8(*sequence)
                    .u8(*flags)
                    .bytes(extensions);
            }
            Self::Other(o) => {
                w.bytes(&o.body);
            }
        }
    }

    /// Serialize the message with its checksum for a packet from `src` to
    /// `dst`.
    pub fn to_bytes(&self, src: &Ipv6Addr, dst: &Ipv6Addr) -> Vec<u8> {
        let mut out = Vec::new();
        self.write_to(src, dst, &mut out);
        out
    }

    /// Serialize the message with a zero checksum field, for a socket, whose
    /// kernel fills the checksum in.
    pub fn to_bytes_unchecksummed(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write_to_unchecksummed(&mut out);
        out
    }

    /// Append the serialized message, with its checksum for a packet from
    /// `src` to `dst`, to `out`.
    pub fn write_to(&self, src: &Ipv6Addr, dst: &Ipv6Addr, out: &mut Vec<u8>) {
        let start = out.len();
        self.write_body(out);
        let len = out.len() - start;
        checksum::fill(
            &mut out[start..],
            checksum::ipv6_pseudo_header(src, dst, len),
        );
    }

    /// Append the serialized message, with a zero checksum field, to `out`.
    pub fn write_to_unchecksummed(&self, out: &mut Vec<u8>) {
        self.write_body(out);
    }

    /// Whether the checksum of a received ICMPv6 message is correct. `bytes`
    /// is the message as received, beginning at the type field; `src` is the
    /// address it came from and `dst` the address it was sent to.
    ///
    /// The kernel already verified packets received on an ICMPv6 socket and
    /// dropped those that fail. Use this for packets from other sources.
    pub fn verify_checksum(bytes: &[u8], src: &Ipv6Addr, dst: &Ipv6Addr) -> bool {
        checksum::verifies(bytes, checksum::ipv6_pseudo_header(src, dst, bytes.len()))
    }
}

impl TryFrom<&[u8]> for Icmpv6Message {
    type Error = ParseError;

    /// Same as [`Icmpv6Message::parse`].
    fn try_from(bytes: &[u8]) -> Result<Self, ParseError> {
        Self::parse(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LO: Ipv6Addr = Ipv6Addr::LOCALHOST;

    fn round_trip(msg: Icmpv6Message) {
        let bytes = msg.to_bytes(&LO, &LO);
        assert!(
            Icmpv6Message::verify_checksum(&bytes, &LO, &LO),
            "{:?}",
            msg
        );
        assert_eq!(Icmpv6Message::parse(&bytes).unwrap(), msg);
        let plain = msg.to_bytes_unchecksummed();
        assert_eq!(&plain[2..4], &[0, 0]);
        assert_eq!(Icmpv6Message::parse(&plain).unwrap(), msg);
    }

    #[test]
    fn every_variant_round_trips() {
        let original = vec![0x60, 0, 0, 0, 1, 2, 3, 4];
        let options = vec![1, 1, 1, 2, 3, 4, 5, 6];
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        for msg in [
            Icmpv6Message::echo_request(42, 7, vec![1, 2, 3]),
            Icmpv6Message::echo_reply(42, 7, vec![]),
            Icmpv6Message::DestinationUnreachable {
                code: unreachable_code::PORT,
                rest: [0; 4],
                original: original.clone(),
            },
            Icmpv6Message::PacketTooBig {
                code: 0,
                mtu: 1280,
                original: original.clone(),
            },
            Icmpv6Message::TimeExceeded {
                code: time_exceeded_code::HOP_LIMIT,
                rest: [0; 4],
                original: original.clone(),
            },
            Icmpv6Message::ParameterProblem {
                code: parameter_problem_code::UNRECOGNIZED_OPTION,
                pointer: 40,
                original: original.clone(),
            },
            Icmpv6Message::MulticastListenerQuery {
                code: 0,
                maximum_response: 1000,
                reserved: 0,
                multicast_address: Ipv6Addr::UNSPECIFIED,
                v2: vec![],
            },
            Icmpv6Message::MulticastListenerQuery {
                code: 0,
                maximum_response: 1000,
                reserved: 0,
                multicast_address: Ipv6Addr::UNSPECIFIED,
                v2: vec![0x02, 125, 0, 0],
            },
            Icmpv6Message::MulticastListenerReport {
                code: 0,
                maximum_response: 0,
                reserved: 0,
                multicast_address: addr,
                trailing: vec![],
            },
            Icmpv6Message::MulticastListenerDone {
                code: 0,
                maximum_response: 0,
                reserved: 0,
                multicast_address: addr,
                trailing: vec![],
            },
            Icmpv6Message::RouterSolicitation {
                code: 0,
                reserved: [0; 4],
                options: options.clone(),
            },
            Icmpv6Message::RouterAdvertisement {
                code: 0,
                cur_hop_limit: 64,
                flags: router_advertisement_flags::MANAGED,
                router_lifetime: 1800,
                reachable_time: 0,
                retrans_timer: 0,
                options: options.clone(),
            },
            Icmpv6Message::NeighborSolicitation {
                code: 0,
                reserved: [0; 4],
                target: addr,
                options: options.clone(),
            },
            Icmpv6Message::NeighborAdvertisement {
                code: 0,
                flags: neighbor_advertisement_flags::SOLICITED,
                target: addr,
                options: options.clone(),
            },
            Icmpv6Message::Redirect {
                code: 0,
                reserved: [0; 4],
                target: addr,
                destination: LO,
                options: options.clone(),
            },
            Icmpv6Message::RouterRenumbering {
                code: router_renumbering_code::COMMAND,
                sequence_number: 1,
                segment_number: 2,
                flags: 0,
                max_delay: 100,
                reserved: 0,
                body: vec![1, 2],
            },
            Icmpv6Message::NodeInformationQuery {
                code: node_information_query_code::IPV6_SUBJECT,
                qtype: 2,
                flags: 0,
                nonce: [1; 8],
                data: addr.octets().to_vec(),
            },
            Icmpv6Message::NodeInformationResponse {
                code: node_information_response_code::SUCCESS,
                qtype: 2,
                flags: 0,
                nonce: [1; 8],
                data: vec![],
            },
            Icmpv6Message::InverseNeighborSolicitation {
                code: 0,
                reserved: [0; 4],
                options: options.clone(),
            },
            Icmpv6Message::InverseNeighborAdvertisement {
                code: 0,
                reserved: [0; 4],
                options: options.clone(),
            },
            Icmpv6Message::MulticastListenerReportV2 {
                code: 0,
                flags: 0,
                record_count: 0,
                records: vec![],
            },
            Icmpv6Message::HomeAgentAddressDiscoveryRequest {
                code: 0,
                identifier: 5,
                reserved: 0,
            },
            Icmpv6Message::HomeAgentAddressDiscoveryReply {
                code: 0,
                identifier: 5,
                reserved: 0,
                addresses: addr.octets().to_vec(),
            },
            Icmpv6Message::MobilePrefixSolicitation {
                code: 0,
                identifier: 5,
                reserved: 0,
                options: vec![],
            },
            Icmpv6Message::MobilePrefixAdvertisement {
                code: 0,
                identifier: 5,
                flags: 0x8000,
                options: options.clone(),
            },
            Icmpv6Message::CertificationPathSolicitation {
                code: 0,
                identifier: 5,
                component: 65535,
                options: vec![],
            },
            Icmpv6Message::CertificationPathAdvertisement {
                code: 0,
                identifier: 5,
                all_components: 2,
                component: 1,
                reserved: 0,
                options: options.clone(),
            },
            Icmpv6Message::ExperimentalMobility {
                code: 0,
                subtype: 1,
                reserved: [0; 3],
                body: vec![9],
            },
            Icmpv6Message::MulticastRouterAdvertisement {
                advertisement_interval: 20,
                query_interval: 125,
                robustness_variable: 2,
            },
            Icmpv6Message::MulticastRouterSolicitation { reserved: 0 },
            Icmpv6Message::MulticastRouterTermination { reserved: 0 },
            Icmpv6Message::Fmipv6 {
                code: 0,
                subtype: 2,
                reserved: 0,
                identifier: 9,
                options: options.clone(),
            },
            Icmpv6Message::RplControl {
                code: rpl_code::DIS,
                body: vec![0, 0],
            },
            Icmpv6Message::Ilnpv6LocatorUpdate {
                code: 0,
                num_locators: 1,
                operation: 1,
                reserved: 0,
                locators: vec![0; 12],
            },
            Icmpv6Message::DuplicateAddressRequest {
                code: 0,
                status: 0,
                tid: 0,
                registration_lifetime: 60,
                rovr: vec![1; 8],
                registered_address: addr,
            },
            Icmpv6Message::DuplicateAddressConfirmation {
                code: 4,
                status: 0,
                tid: 1,
                registration_lifetime: 60,
                rovr: vec![2; 32],
                registered_address: addr,
            },
            Icmpv6Message::MplControl {
                code: 0,
                seed_info: vec![1, 0],
            },
            Icmpv6Message::ExtendedEchoRequest {
                code: 0,
                identifier: 1,
                sequence: 2,
                flags: extended_echo_flags::LOCAL,
                extensions: vec![0x20, 0, 0, 0],
            },
            Icmpv6Message::ExtendedEchoReply {
                code: extended_echo_reply_code::NO_SUCH_INTERFACE,
                identifier: 1,
                sequence: 2,
                flags: 0,
                extensions: vec![],
            },
            Icmpv6Message::Other(Icmpv6Other::new(200, 0, vec![1, 2, 3, 4]).unwrap()),
        ] {
            round_trip(msg);
        }
    }

    #[test]
    fn every_assigned_type_has_a_variant() {
        for typ in 0..=255u8 {
            let mut bytes = vec![typ, 0, 0, 0];
            bytes.resize(48, 0);
            // Fixed-length types parse at exactly their length.
            let parsed = (4..=bytes.len())
                .find_map(|n| Icmpv6Message::parse(&bytes[..n]).ok())
                .unwrap();
            assert_eq!(parsed.typ(), typ);
            assert_eq!(
                matches!(parsed, Icmpv6Message::Other(_)),
                !is_modelled(typ),
                "type {}",
                typ
            );
        }
    }

    #[test]
    fn checksum_depends_on_the_addresses() {
        let other = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let bytes = Icmpv6Message::echo_request(1, 1, vec![9]).to_bytes(&LO, &LO);
        assert!(!Icmpv6Message::verify_checksum(&bytes, &other, &LO));
    }

    #[test]
    fn length_rules() {
        assert_eq!(
            Icmpv6Message::parse(&[128, 0, 0, 0, 0]),
            Err(ParseError::TooShort {
                needed: 8,
                actual: 5
            })
        );
        // An MLD query of 26 bytes is neither MLDv1 (24) nor MLDv2 (28+).
        let mut query = vec![130, 0, 0, 0];
        query.resize(26, 0);
        assert_eq!(
            Icmpv6Message::parse(&query),
            Err(ParseError::TooShort {
                needed: 28,
                actual: 26
            })
        );
        assert_eq!(
            Icmpv6Message::parse(&[152, 0, 0, 0, 1]),
            Err(ParseError::TrailingBytes {
                expected: 4,
                actual: 5
            })
        );
    }

    #[test]
    fn other_rejects_modelled_types() {
        assert_eq!(
            Icmpv6Other::new(128, 0, vec![]),
            Err(ModelledTypeError { typ: 128 })
        );
    }

    #[test]
    fn accessors() {
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let reply = Icmpv6Message::HomeAgentAddressDiscoveryReply {
            code: 0,
            identifier: 1,
            reserved: 0,
            addresses: [addr.octets(), LO.octets()].concat(),
        };
        assert_eq!(reply.home_agent_addresses(), Some(vec![addr, LO]));
        let rs = Icmpv6Message::RouterSolicitation {
            code: 0,
            reserved: [0; 4],
            options: vec![1, 1, 0, 0, 0, 0, 0, 1],
        };
        assert_eq!(rs.nd_options(), Some(&[1, 1, 0, 0, 0, 0, 0, 1][..]));
        let mut original = vec![0; 8];
        original.extend([0x20, 0, 0, 0]);
        let unreach = Icmpv6Message::DestinationUnreachable {
            code: 0,
            rest: [1, 0, 0, 0],
            original,
        };
        assert_eq!(unreach.extensions(), Some(&[0x20, 0, 0, 0][..]));
    }
}
