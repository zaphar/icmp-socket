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
//! ICMPv4 messages.
//!
//! [`Icmpv4Message`] has a variant for every type in the IANA "ICMP Type
//! Numbers" registry; other numbers parse as [`Icmpv4Message::Other`]. A
//! message is one ICMP message without its IPv4 header.
//!
//! Fields whose meaning depends on the code or on a later RFC are kept raw
//! (`rest`), with accessor methods. Lists of records are kept as bytes, also
//! with accessor methods. Deprecated types are modelled too, because they
//! still appear on the wire; each says which RFC deprecated it.
use std::net::Ipv4Addr;

use crate::checksum;
use crate::error::ParseError;
use crate::wire::{Reader, Writer, check_header};

/// ICMPv4 type numbers.
pub mod msg_type {
    pub const ECHO_REPLY: u8 = 0;
    pub const DESTINATION_UNREACHABLE: u8 = 3;
    pub const SOURCE_QUENCH: u8 = 4;
    pub const REDIRECT: u8 = 5;
    pub const ALTERNATE_HOST_ADDRESS: u8 = 6;
    pub const ECHO_REQUEST: u8 = 8;
    pub const ROUTER_ADVERTISEMENT: u8 = 9;
    pub const ROUTER_SOLICITATION: u8 = 10;
    pub const TIME_EXCEEDED: u8 = 11;
    pub const PARAMETER_PROBLEM: u8 = 12;
    pub const TIMESTAMP: u8 = 13;
    pub const TIMESTAMP_REPLY: u8 = 14;
    pub const INFORMATION_REQUEST: u8 = 15;
    pub const INFORMATION_REPLY: u8 = 16;
    pub const ADDRESS_MASK_REQUEST: u8 = 17;
    pub const ADDRESS_MASK_REPLY: u8 = 18;
    pub const TRACEROUTE: u8 = 30;
    pub const DATAGRAM_CONVERSION_ERROR: u8 = 31;
    pub const MOBILE_HOST_REDIRECT: u8 = 32;
    pub const IPV6_WHERE_ARE_YOU: u8 = 33;
    pub const IPV6_I_AM_HERE: u8 = 34;
    pub const MOBILE_REGISTRATION_REQUEST: u8 = 35;
    pub const MOBILE_REGISTRATION_REPLY: u8 = 36;
    pub const DOMAIN_NAME_REQUEST: u8 = 37;
    pub const DOMAIN_NAME_REPLY: u8 = 38;
    pub const SKIP: u8 = 39;
    pub const PHOTURIS: u8 = 40;
    pub const EXPERIMENTAL_MOBILITY: u8 = 41;
    pub const EXTENDED_ECHO_REQUEST: u8 = 42;
    pub const EXTENDED_ECHO_REPLY: u8 = 43;
}

/// Destination Unreachable codes (RFC 792, RFC 1122, RFC 1812).
pub mod unreachable_code {
    pub const NETWORK: u8 = 0;
    pub const HOST: u8 = 1;
    pub const PROTOCOL: u8 = 2;
    pub const PORT: u8 = 3;
    pub const FRAGMENTATION_NEEDED: u8 = 4;
    pub const SOURCE_ROUTE_FAILED: u8 = 5;
    pub const DESTINATION_NETWORK_UNKNOWN: u8 = 6;
    pub const DESTINATION_HOST_UNKNOWN: u8 = 7;
    pub const SOURCE_HOST_ISOLATED: u8 = 8;
    pub const NETWORK_ADMINISTRATIVELY_PROHIBITED: u8 = 9;
    pub const HOST_ADMINISTRATIVELY_PROHIBITED: u8 = 10;
    pub const NETWORK_UNREACHABLE_FOR_TOS: u8 = 11;
    pub const HOST_UNREACHABLE_FOR_TOS: u8 = 12;
    pub const COMMUNICATION_ADMINISTRATIVELY_PROHIBITED: u8 = 13;
    pub const HOST_PRECEDENCE_VIOLATION: u8 = 14;
    pub const PRECEDENCE_CUTOFF: u8 = 15;
}

/// Redirect codes (RFC 792).
pub mod redirect_code {
    pub const NETWORK: u8 = 0;
    pub const HOST: u8 = 1;
    pub const TOS_AND_NETWORK: u8 = 2;
    pub const TOS_AND_HOST: u8 = 3;
}

/// Router Advertisement codes (RFC 5944).
pub mod router_advertisement_code {
    pub const NORMAL: u8 = 0;
    pub const DOES_NOT_ROUTE_COMMON_TRAFFIC: u8 = 16;
}

/// Time Exceeded codes (RFC 792).
pub mod time_exceeded_code {
    pub const TTL: u8 = 0;
    pub const FRAGMENT_REASSEMBLY: u8 = 1;
}

/// Parameter Problem codes (RFC 792, RFC 1108).
pub mod parameter_problem_code {
    pub const POINTER: u8 = 0;
    pub const MISSING_OPTION: u8 = 1;
    pub const BAD_LENGTH: u8 = 2;
}

/// Traceroute codes (RFC 1393; not in the IANA registry).
pub mod traceroute_code {
    pub const FORWARDED: u8 = 0;
    pub const NO_ROUTE: u8 = 1;
}

/// Photuris codes (RFC 2521).
pub mod photuris_code {
    pub const BAD_SPI: u8 = 0;
    pub const AUTHENTICATION_FAILED: u8 = 1;
    pub const DECOMPRESSION_FAILED: u8 = 2;
    pub const DECRYPTION_FAILED: u8 = 3;
    pub const NEED_AUTHENTICATION: u8 = 4;
    pub const NEED_AUTHORIZATION: u8 = 5;
}

/// Extended Echo Reply codes (RFC 8335).
pub mod extended_echo_reply_code {
    pub const NO_ERROR: u8 = 0;
    pub const MALFORMED_QUERY: u8 = 1;
    pub const NO_SUCH_INTERFACE: u8 = 2;
    pub const NO_SUCH_TABLE_ENTRY: u8 = 3;
    pub const MULTIPLE_INTERFACES_SATISFY_QUERY: u8 = 4;
}

/// Bits of the Extended Echo `flags` byte (RFC 8335).
pub mod extended_echo_flags {
    /// Request: the probed interface is on the proxy node.
    pub const LOCAL: u8 = 0x01;
    /// Reply: the probed interface is active.
    pub const ACTIVE: u8 = 0x04;
    /// Reply: IPv4 runs on the probed interface.
    pub const IPV4: u8 = 0x02;
    /// Reply: IPv6 runs on the probed interface.
    pub const IPV6: u8 = 0x01;
    /// Reply: the neighbor state (`(flags & STATE_MASK) >> STATE_SHIFT`).
    pub const STATE_MASK: u8 = 0xE0;
    pub const STATE_SHIFT: u8 = 5;
}

/// An ICMPv4 message. The variant is the message type; [`Self::typ`]
/// returns its number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Icmpv4Message {
    /// Type 0 (RFC 792).
    EchoReply {
        code: u8,
        identifier: u16,
        sequence: u16,
        payload: Vec<u8>,
    },
    /// Type 3 (RFC 792). `rest` holds bytes 4..8, whose meaning depends on
    /// the code; see [`Icmpv4Message::next_hop_mtu`] and
    /// [`Icmpv4Message::extensions`]. `original` is the start of the
    /// datagram that caused the error (plus any RFC 4884 extensions).
    DestinationUnreachable {
        code: u8,
        rest: [u8; 4],
        original: Vec<u8>,
    },
    /// Type 4 (RFC 792). Deprecated by RFC 6633.
    SourceQuench {
        code: u8,
        unused: [u8; 4],
        original: Vec<u8>,
    },
    /// Type 5 (RFC 792).
    Redirect {
        code: u8,
        gateway: Ipv4Addr,
        original: Vec<u8>,
    },
    /// Type 6. Deprecated by RFC 6918; no public specification, so the body
    /// (bytes 4..) is kept as is.
    AlternateHostAddress { code: u8, body: Vec<u8> },
    /// Type 8 (RFC 792).
    EchoRequest {
        code: u8,
        identifier: u16,
        sequence: u16,
        payload: Vec<u8>,
    },
    /// Type 9 (RFC 1256, RFC 5944). `body` holds the address entries and
    /// any Mobile IPv4 extensions; see
    /// [`Icmpv4Message::router_addresses`].
    RouterAdvertisement {
        code: u8,
        num_addrs: u8,
        addr_entry_size: u8,
        lifetime: u16,
        body: Vec<u8>,
    },
    /// Type 10 (RFC 1256). RFC 1256 tells receivers to ignore bytes after
    /// the first 8; they are kept in `trailing`.
    RouterSolicitation {
        code: u8,
        reserved: [u8; 4],
        trailing: Vec<u8>,
    },
    /// Type 11 (RFC 792). `rest` holds bytes 4..8; see
    /// [`Icmpv4Message::extensions`].
    TimeExceeded {
        code: u8,
        rest: [u8; 4],
        original: Vec<u8>,
    },
    /// Type 12 (RFC 792). `pointer` is the offset of the bad octet; `rest`
    /// holds bytes 5..8.
    ParameterProblem {
        code: u8,
        pointer: u8,
        rest: [u8; 3],
        original: Vec<u8>,
    },
    /// Type 13 (RFC 792). Exactly 20 bytes.
    Timestamp {
        code: u8,
        identifier: u16,
        sequence: u16,
        originate: u32,
        receive: u32,
        transmit: u32,
    },
    /// Type 14 (RFC 792). Exactly 20 bytes.
    TimestampReply {
        code: u8,
        identifier: u16,
        sequence: u16,
        originate: u32,
        receive: u32,
        transmit: u32,
    },
    /// Type 15 (RFC 792). Exactly 8 bytes. Deprecated by RFC 6918.
    InformationRequest {
        code: u8,
        identifier: u16,
        sequence: u16,
    },
    /// Type 16 (RFC 792). Exactly 8 bytes. Deprecated by RFC 6918.
    InformationReply {
        code: u8,
        identifier: u16,
        sequence: u16,
    },
    /// Type 17 (RFC 950). Exactly 12 bytes. Deprecated by RFC 6918.
    AddressMaskRequest {
        code: u8,
        identifier: u16,
        sequence: u16,
        address_mask: Ipv4Addr,
    },
    /// Type 18 (RFC 950). Exactly 12 bytes. Deprecated by RFC 6918.
    AddressMaskReply {
        code: u8,
        identifier: u16,
        sequence: u16,
        address_mask: Ipv4Addr,
    },
    /// Type 30 (RFC 1393). Exactly 20 bytes. Deprecated by RFC 6918.
    Traceroute {
        code: u8,
        id: u16,
        unused: u16,
        outbound_hop_count: u16,
        return_hop_count: u16,
        output_link_speed: u32,
        output_link_mtu: u32,
    },
    /// Type 31 (RFC 1475). Deprecated by RFC 6918.
    DatagramConversionError {
        code: u8,
        pointer: u32,
        original: Vec<u8>,
    },
    /// Type 32. Deprecated by RFC 6918; no public specification.
    MobileHostRedirect { code: u8, body: Vec<u8> },
    /// Type 33. Deprecated by RFC 6918; no public specification.
    Ipv6WhereAreYou { code: u8, body: Vec<u8> },
    /// Type 34. Deprecated by RFC 6918; no public specification.
    Ipv6IAmHere { code: u8, body: Vec<u8> },
    /// Type 35. Deprecated by RFC 6918; no public specification.
    MobileRegistrationRequest { code: u8, body: Vec<u8> },
    /// Type 36. Deprecated by RFC 6918; no public specification.
    MobileRegistrationReply { code: u8, body: Vec<u8> },
    /// Type 37 (RFC 1788). Exactly 8 bytes. Deprecated by RFC 6918.
    DomainNameRequest {
        code: u8,
        identifier: u16,
        sequence: u16,
    },
    /// Type 38 (RFC 1788). `names` are DNS names in wire format. Deprecated
    /// by RFC 6918.
    DomainNameReply {
        code: u8,
        identifier: u16,
        sequence: u16,
        ttl: i32,
        names: Vec<u8>,
    },
    /// Type 39. Deprecated by RFC 6918; no public specification.
    Skip { code: u8, body: Vec<u8> },
    /// Type 40 (RFC 2521, "Security Failures").
    Photuris {
        code: u8,
        reserved: u16,
        pointer: u16,
        original: Vec<u8>,
    },
    /// Type 41 (RFC 4065): messages of experimental mobility protocols such
    /// as Seamoby. `body` is defined by the protocol `subtype` names.
    ExperimentalMobility {
        code: u8,
        subtype: u8,
        reserved: [u8; 3],
        body: Vec<u8>,
    },
    /// Type 42 (RFC 8335). The sequence number has 8 bits. `flags` holds
    /// [`extended_echo_flags::LOCAL`]; `extensions` is the RFC 4884
    /// extension structure naming the probed interface.
    ExtendedEchoRequest {
        code: u8,
        identifier: u16,
        sequence: u8,
        flags: u8,
        extensions: Vec<u8>,
    },
    /// Type 43 (RFC 8335). `flags` holds the state and the A, 4 and 6 bits;
    /// see [`extended_echo_flags`].
    ExtendedEchoReply {
        code: u8,
        identifier: u16,
        sequence: u8,
        flags: u8,
        extensions: Vec<u8>,
    },
    /// A type this crate does not model: unassigned, reserved and
    /// experimental numbers.
    Other(Icmpv4Other),
}

/// An ICMPv4 message of a type that has no variant of its own: its type,
/// code and the bytes after the checksum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmpv4Other {
    typ: u8,
    code: u8,
    body: Vec<u8>,
}

impl Icmpv4Other {
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

/// One router address entry of a Router Advertisement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouterAddress {
    pub address: Ipv4Addr,
    /// Higher is more preferred.
    pub preference: i32,
}

impl Icmpv4Message {
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

    /// A message from its type, code and the bytes after the checksum. A
    /// type with its own variant gives that variant, as [`Self::parse`] does.
    pub fn from_parts(typ: u8, code: u8, body: &[u8]) -> Result<Self, ParseError> {
        let mut bytes = Vec::with_capacity(4 + body.len());
        bytes.extend_from_slice(&[typ, code, 0, 0]);
        bytes.extend_from_slice(body);
        Self::parse(&bytes)
    }

    /// The type number.
    pub fn typ(&self) -> u8 {
        use msg_type::*;
        match self {
            Self::EchoReply { .. } => ECHO_REPLY,
            Self::DestinationUnreachable { .. } => DESTINATION_UNREACHABLE,
            Self::SourceQuench { .. } => SOURCE_QUENCH,
            Self::Redirect { .. } => REDIRECT,
            Self::AlternateHostAddress { .. } => ALTERNATE_HOST_ADDRESS,
            Self::EchoRequest { .. } => ECHO_REQUEST,
            Self::RouterAdvertisement { .. } => ROUTER_ADVERTISEMENT,
            Self::RouterSolicitation { .. } => ROUTER_SOLICITATION,
            Self::TimeExceeded { .. } => TIME_EXCEEDED,
            Self::ParameterProblem { .. } => PARAMETER_PROBLEM,
            Self::Timestamp { .. } => TIMESTAMP,
            Self::TimestampReply { .. } => TIMESTAMP_REPLY,
            Self::InformationRequest { .. } => INFORMATION_REQUEST,
            Self::InformationReply { .. } => INFORMATION_REPLY,
            Self::AddressMaskRequest { .. } => ADDRESS_MASK_REQUEST,
            Self::AddressMaskReply { .. } => ADDRESS_MASK_REPLY,
            Self::Traceroute { .. } => TRACEROUTE,
            Self::DatagramConversionError { .. } => DATAGRAM_CONVERSION_ERROR,
            Self::MobileHostRedirect { .. } => MOBILE_HOST_REDIRECT,
            Self::Ipv6WhereAreYou { .. } => IPV6_WHERE_ARE_YOU,
            Self::Ipv6IAmHere { .. } => IPV6_I_AM_HERE,
            Self::MobileRegistrationRequest { .. } => MOBILE_REGISTRATION_REQUEST,
            Self::MobileRegistrationReply { .. } => MOBILE_REGISTRATION_REPLY,
            Self::DomainNameRequest { .. } => DOMAIN_NAME_REQUEST,
            Self::DomainNameReply { .. } => DOMAIN_NAME_REPLY,
            Self::Skip { .. } => SKIP,
            Self::Photuris { .. } => PHOTURIS,
            Self::ExperimentalMobility { .. } => EXPERIMENTAL_MOBILITY,
            Self::ExtendedEchoRequest { .. } => EXTENDED_ECHO_REQUEST,
            Self::ExtendedEchoReply { .. } => EXTENDED_ECHO_REPLY,
            Self::Other(o) => o.typ,
        }
    }

    /// The code.
    pub fn code(&self) -> u8 {
        match self {
            Self::EchoReply { code, .. }
            | Self::DestinationUnreachable { code, .. }
            | Self::SourceQuench { code, .. }
            | Self::Redirect { code, .. }
            | Self::AlternateHostAddress { code, .. }
            | Self::EchoRequest { code, .. }
            | Self::RouterAdvertisement { code, .. }
            | Self::RouterSolicitation { code, .. }
            | Self::TimeExceeded { code, .. }
            | Self::ParameterProblem { code, .. }
            | Self::Timestamp { code, .. }
            | Self::TimestampReply { code, .. }
            | Self::InformationRequest { code, .. }
            | Self::InformationReply { code, .. }
            | Self::AddressMaskRequest { code, .. }
            | Self::AddressMaskReply { code, .. }
            | Self::Traceroute { code, .. }
            | Self::DatagramConversionError { code, .. }
            | Self::MobileHostRedirect { code, .. }
            | Self::Ipv6WhereAreYou { code, .. }
            | Self::Ipv6IAmHere { code, .. }
            | Self::MobileRegistrationRequest { code, .. }
            | Self::MobileRegistrationReply { code, .. }
            | Self::DomainNameRequest { code, .. }
            | Self::DomainNameReply { code, .. }
            | Self::Skip { code, .. }
            | Self::Photuris { code, .. }
            | Self::ExperimentalMobility { code, .. }
            | Self::ExtendedEchoRequest { code, .. }
            | Self::ExtendedEchoReply { code, .. } => *code,
            Self::Other(o) => o.code,
        }
    }

    /// The next-hop MTU of a Destination Unreachable, Fragmentation Needed
    /// message (RFC 1191), or `None` for any other message. 0 means the
    /// router did not report one.
    pub fn next_hop_mtu(&self) -> Option<u16> {
        match self {
            Self::DestinationUnreachable { code, rest, .. }
                if *code == unreachable_code::FRAGMENTATION_NEEDED =>
            {
                Some(u16::from_be_bytes([rest[2], rest[3]]))
            }
            _ => None,
        }
    }

    /// The length in bytes of the original datagram when the message carries
    /// RFC 4884 extensions after it, or `None` when the length field is 0
    /// (no extensions) or the type has no such field.
    pub fn extension_length(&self) -> Option<usize> {
        let words = match self {
            Self::DestinationUnreachable { rest, .. } | Self::TimeExceeded { rest, .. } => rest[1],
            Self::ParameterProblem { rest, .. } => rest[0],
            _ => return None,
        };
        (words != 0).then_some(usize::from(words) * 4)
    }

    /// The RFC 4884 extension structure the message carries, if any: after
    /// the original datagram of an error message, or the body of an
    /// Extended Echo message. Read it with
    /// [`crate::options::ExtensionHeader::split`].
    pub fn extensions(&self) -> Option<&[u8]> {
        match self {
            Self::DestinationUnreachable { original, .. }
            | Self::TimeExceeded { original, .. }
            | Self::ParameterProblem { original, .. } => {
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

    /// The router address entries of a Router Advertisement, or `None` for
    /// any other message. Entries beyond the message's length are left out;
    /// words after the first two of an entry are ignored (RFC 1256).
    pub fn router_addresses(&self) -> Option<Vec<RouterAddress>> {
        let Self::RouterAdvertisement {
            num_addrs,
            addr_entry_size,
            body,
            ..
        } = self
        else {
            return None;
        };
        let stride = usize::from(*addr_entry_size) * 4;
        if stride < 8 {
            return Some(Vec::new());
        }
        Some(
            body.chunks_exact(stride)
                .take(usize::from(*num_addrs))
                .map(|e| RouterAddress {
                    address: Ipv4Addr::new(e[0], e[1], e[2], e[3]),
                    preference: i32::from_be_bytes([e[4], e[5], e[6], e[7]]),
                })
                .collect(),
        )
    }

    /// Parse one ICMPv4 message. `bytes` begins at the type field, with no
    /// IPv4 header. The checksum is not checked; see
    /// [`Self::verify_checksum`].
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        use msg_type::*;
        check_header(bytes)?;
        let (typ, code) = (bytes[0], bytes[1]);
        let mut r = Reader::after_header(bytes);
        Ok(match typ {
            ECHO_REPLY | ECHO_REQUEST => {
                r.need(8)?;
                let (identifier, sequence, payload) = (r.u16()?, r.u16()?, r.rest());
                if typ == ECHO_REPLY {
                    Self::EchoReply {
                        code,
                        identifier,
                        sequence,
                        payload,
                    }
                } else {
                    Self::EchoRequest {
                        code,
                        identifier,
                        sequence,
                        payload,
                    }
                }
            }
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
            SOURCE_QUENCH => {
                r.need(8)?;
                Self::SourceQuench {
                    code,
                    unused: r.array()?,
                    original: r.rest(),
                }
            }
            REDIRECT => {
                r.need(8)?;
                Self::Redirect {
                    code,
                    gateway: r.ipv4()?,
                    original: r.rest(),
                }
            }
            ROUTER_ADVERTISEMENT => {
                r.need(8)?;
                Self::RouterAdvertisement {
                    code,
                    num_addrs: r.u8()?,
                    addr_entry_size: r.u8()?,
                    lifetime: r.u16()?,
                    body: r.rest(),
                }
            }
            ROUTER_SOLICITATION => {
                r.need(8)?;
                Self::RouterSolicitation {
                    code,
                    reserved: r.array()?,
                    trailing: r.rest(),
                }
            }
            PARAMETER_PROBLEM => {
                r.need(8)?;
                Self::ParameterProblem {
                    code,
                    pointer: r.u8()?,
                    rest: r.array()?,
                    original: r.rest(),
                }
            }
            TIMESTAMP | TIMESTAMP_REPLY => {
                r.exactly(20)?;
                let (identifier, sequence) = (r.u16()?, r.u16()?);
                let (originate, receive, transmit) = (r.u32()?, r.u32()?, r.u32()?);
                if typ == TIMESTAMP {
                    Self::Timestamp {
                        code,
                        identifier,
                        sequence,
                        originate,
                        receive,
                        transmit,
                    }
                } else {
                    Self::TimestampReply {
                        code,
                        identifier,
                        sequence,
                        originate,
                        receive,
                        transmit,
                    }
                }
            }
            INFORMATION_REQUEST | INFORMATION_REPLY | DOMAIN_NAME_REQUEST => {
                r.exactly(8)?;
                let (identifier, sequence) = (r.u16()?, r.u16()?);
                match typ {
                    INFORMATION_REQUEST => Self::InformationRequest {
                        code,
                        identifier,
                        sequence,
                    },
                    INFORMATION_REPLY => Self::InformationReply {
                        code,
                        identifier,
                        sequence,
                    },
                    _ => Self::DomainNameRequest {
                        code,
                        identifier,
                        sequence,
                    },
                }
            }
            ADDRESS_MASK_REQUEST | ADDRESS_MASK_REPLY => {
                r.exactly(12)?;
                let (identifier, sequence, address_mask) = (r.u16()?, r.u16()?, r.ipv4()?);
                if typ == ADDRESS_MASK_REQUEST {
                    Self::AddressMaskRequest {
                        code,
                        identifier,
                        sequence,
                        address_mask,
                    }
                } else {
                    Self::AddressMaskReply {
                        code,
                        identifier,
                        sequence,
                        address_mask,
                    }
                }
            }
            TRACEROUTE => {
                r.exactly(20)?;
                Self::Traceroute {
                    code,
                    id: r.u16()?,
                    unused: r.u16()?,
                    outbound_hop_count: r.u16()?,
                    return_hop_count: r.u16()?,
                    output_link_speed: r.u32()?,
                    output_link_mtu: r.u32()?,
                }
            }
            DATAGRAM_CONVERSION_ERROR => {
                r.need(8)?;
                Self::DatagramConversionError {
                    code,
                    pointer: r.u32()?,
                    original: r.rest(),
                }
            }
            DOMAIN_NAME_REPLY => {
                r.need(12)?;
                Self::DomainNameReply {
                    code,
                    identifier: r.u16()?,
                    sequence: r.u16()?,
                    ttl: r.u32()? as i32,
                    names: r.rest(),
                }
            }
            PHOTURIS => {
                r.need(8)?;
                Self::Photuris {
                    code,
                    reserved: r.u16()?,
                    pointer: r.u16()?,
                    original: r.rest(),
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
            ALTERNATE_HOST_ADDRESS => Self::AlternateHostAddress {
                code,
                body: r.rest(),
            },
            MOBILE_HOST_REDIRECT => Self::MobileHostRedirect {
                code,
                body: r.rest(),
            },
            IPV6_WHERE_ARE_YOU => Self::Ipv6WhereAreYou {
                code,
                body: r.rest(),
            },
            IPV6_I_AM_HERE => Self::Ipv6IAmHere {
                code,
                body: r.rest(),
            },
            MOBILE_REGISTRATION_REQUEST => Self::MobileRegistrationRequest {
                code,
                body: r.rest(),
            },
            MOBILE_REGISTRATION_REPLY => Self::MobileRegistrationReply {
                code,
                body: r.rest(),
            },
            SKIP => Self::Skip {
                code,
                body: r.rest(),
            },
            _ => Self::Other(Icmpv4Other {
                typ,
                code,
                body: r.rest(),
            }),
        })
    }

    /// Serialize the message with its checksum.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write_to(&mut out);
        out
    }

    /// Append the serialized message, with its checksum, to `out`.
    pub fn write_to(&self, out: &mut Vec<u8>) {
        let start = out.len();
        let mut w = Writer::header(out, self.typ(), self.code());
        match self {
            Self::EchoReply {
                identifier,
                sequence,
                payload,
                ..
            }
            | Self::EchoRequest {
                identifier,
                sequence,
                payload,
                ..
            } => {
                w.u16(*identifier).u16(*sequence).bytes(payload);
            }
            Self::DestinationUnreachable { rest, original, .. }
            | Self::TimeExceeded { rest, original, .. }
            | Self::SourceQuench {
                unused: rest,
                original,
                ..
            }
            | Self::RouterSolicitation {
                reserved: rest,
                trailing: original,
                ..
            } => {
                w.bytes(rest).bytes(original);
            }
            Self::Redirect {
                gateway, original, ..
            } => {
                w.ipv4(gateway).bytes(original);
            }
            Self::RouterAdvertisement {
                num_addrs,
                addr_entry_size,
                lifetime,
                body,
                ..
            } => {
                w.u8(*num_addrs)
                    .u8(*addr_entry_size)
                    .u16(*lifetime)
                    .bytes(body);
            }
            Self::ParameterProblem {
                pointer,
                rest,
                original,
                ..
            } => {
                w.u8(*pointer).bytes(rest).bytes(original);
            }
            Self::Timestamp {
                identifier,
                sequence,
                originate,
                receive,
                transmit,
                ..
            }
            | Self::TimestampReply {
                identifier,
                sequence,
                originate,
                receive,
                transmit,
                ..
            } => {
                w.u16(*identifier)
                    .u16(*sequence)
                    .u32(*originate)
                    .u32(*receive)
                    .u32(*transmit);
            }
            Self::InformationRequest {
                identifier,
                sequence,
                ..
            }
            | Self::InformationReply {
                identifier,
                sequence,
                ..
            }
            | Self::DomainNameRequest {
                identifier,
                sequence,
                ..
            } => {
                w.u16(*identifier).u16(*sequence);
            }
            Self::AddressMaskRequest {
                identifier,
                sequence,
                address_mask,
                ..
            }
            | Self::AddressMaskReply {
                identifier,
                sequence,
                address_mask,
                ..
            } => {
                w.u16(*identifier).u16(*sequence).ipv4(address_mask);
            }
            Self::Traceroute {
                id,
                unused,
                outbound_hop_count,
                return_hop_count,
                output_link_speed,
                output_link_mtu,
                ..
            } => {
                w.u16(*id)
                    .u16(*unused)
                    .u16(*outbound_hop_count)
                    .u16(*return_hop_count)
                    .u32(*output_link_speed)
                    .u32(*output_link_mtu);
            }
            Self::DatagramConversionError {
                pointer, original, ..
            } => {
                w.u32(*pointer).bytes(original);
            }
            Self::DomainNameReply {
                identifier,
                sequence,
                ttl,
                names,
                ..
            } => {
                w.u16(*identifier)
                    .u16(*sequence)
                    .u32(*ttl as u32)
                    .bytes(names);
            }
            Self::Photuris {
                reserved,
                pointer,
                original,
                ..
            } => {
                w.u16(*reserved).u16(*pointer).bytes(original);
            }
            Self::ExperimentalMobility {
                subtype,
                reserved,
                body,
                ..
            } => {
                w.u8(*subtype).bytes(reserved).bytes(body);
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
            Self::AlternateHostAddress { body, .. }
            | Self::MobileHostRedirect { body, .. }
            | Self::Ipv6WhereAreYou { body, .. }
            | Self::Ipv6IAmHere { body, .. }
            | Self::MobileRegistrationRequest { body, .. }
            | Self::MobileRegistrationReply { body, .. }
            | Self::Skip { body, .. } => {
                w.bytes(body);
            }
            Self::Other(o) => {
                w.bytes(&o.body);
            }
        }
        checksum::fill(&mut out[start..], 0);
    }

    /// Whether the checksum of a received ICMPv4 message is correct. `bytes`
    /// is the message as received, beginning at the type field.
    pub fn verify_checksum(bytes: &[u8]) -> bool {
        checksum::verifies(bytes, 0)
    }
}

impl TryFrom<&[u8]> for Icmpv4Message {
    type Error = ParseError;

    /// Same as [`Icmpv4Message::parse`].
    fn try_from(bytes: &[u8]) -> Result<Self, ParseError> {
        Self::parse(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The types with their own variant.
    fn has_variant(typ: u8) -> bool {
        matches!(typ, 0 | 3..=6 | 8..=18 | 30..=43)
    }

    fn round_trip(msg: Icmpv4Message) {
        let bytes = msg.to_bytes();
        assert!(Icmpv4Message::verify_checksum(&bytes), "{:?}", msg);
        assert_eq!(Icmpv4Message::parse(&bytes).unwrap(), msg);
    }

    #[test]
    fn every_variant_round_trips() {
        let original = vec![0x45, 0, 0, 20, 1, 2, 3, 4];
        let body = vec![9, 8, 7];
        for msg in [
            Icmpv4Message::echo_request(42, 7, vec![1, 2, 3]),
            Icmpv4Message::echo_reply(42, 7, vec![]),
            Icmpv4Message::DestinationUnreachable {
                code: unreachable_code::FRAGMENTATION_NEEDED,
                rest: [0, 0, 0x05, 0xdc],
                original: original.clone(),
            },
            Icmpv4Message::SourceQuench {
                code: 0,
                unused: [0; 4],
                original: original.clone(),
            },
            Icmpv4Message::Redirect {
                code: redirect_code::HOST,
                gateway: Ipv4Addr::new(10, 0, 0, 1),
                original: original.clone(),
            },
            Icmpv4Message::AlternateHostAddress {
                code: 0,
                body: body.clone(),
            },
            Icmpv4Message::RouterAdvertisement {
                code: router_advertisement_code::NORMAL,
                num_addrs: 1,
                addr_entry_size: 2,
                lifetime: 1800,
                body: vec![10, 0, 0, 1, 0, 0, 0, 5],
            },
            Icmpv4Message::RouterSolicitation {
                code: 0,
                reserved: [0; 4],
                trailing: vec![],
            },
            Icmpv4Message::TimeExceeded {
                code: time_exceeded_code::TTL,
                rest: [0; 4],
                original: original.clone(),
            },
            Icmpv4Message::ParameterProblem {
                code: parameter_problem_code::POINTER,
                pointer: 9,
                rest: [0; 3],
                original: original.clone(),
            },
            Icmpv4Message::Timestamp {
                code: 0,
                identifier: 1,
                sequence: 2,
                originate: 3,
                receive: 4,
                transmit: 5,
            },
            Icmpv4Message::TimestampReply {
                code: 0,
                identifier: 1,
                sequence: 2,
                originate: 3,
                receive: 4,
                transmit: 5,
            },
            Icmpv4Message::InformationRequest {
                code: 0,
                identifier: 1,
                sequence: 2,
            },
            Icmpv4Message::InformationReply {
                code: 0,
                identifier: 1,
                sequence: 2,
            },
            Icmpv4Message::AddressMaskRequest {
                code: 0,
                identifier: 1,
                sequence: 2,
                address_mask: Ipv4Addr::UNSPECIFIED,
            },
            Icmpv4Message::AddressMaskReply {
                code: 0,
                identifier: 1,
                sequence: 2,
                address_mask: Ipv4Addr::new(255, 255, 255, 0),
            },
            Icmpv4Message::Traceroute {
                code: traceroute_code::FORWARDED,
                id: 1,
                unused: 0,
                outbound_hop_count: 2,
                return_hop_count: 3,
                output_link_speed: 4,
                output_link_mtu: 1500,
            },
            Icmpv4Message::DatagramConversionError {
                code: 0,
                pointer: 4,
                original: original.clone(),
            },
            Icmpv4Message::MobileHostRedirect {
                code: 0,
                body: body.clone(),
            },
            Icmpv4Message::Ipv6WhereAreYou {
                code: 0,
                body: body.clone(),
            },
            Icmpv4Message::Ipv6IAmHere {
                code: 0,
                body: body.clone(),
            },
            Icmpv4Message::MobileRegistrationRequest {
                code: 0,
                body: body.clone(),
            },
            Icmpv4Message::MobileRegistrationReply {
                code: 0,
                body: body.clone(),
            },
            Icmpv4Message::DomainNameRequest {
                code: 0,
                identifier: 1,
                sequence: 2,
            },
            Icmpv4Message::DomainNameReply {
                code: 0,
                identifier: 1,
                sequence: 2,
                ttl: -1,
                names: vec![3, b'w', b'w', b'w', 0],
            },
            Icmpv4Message::Skip {
                code: 0,
                body: body.clone(),
            },
            Icmpv4Message::Photuris {
                code: photuris_code::BAD_SPI,
                reserved: 0,
                pointer: 20,
                original: original.clone(),
            },
            Icmpv4Message::ExperimentalMobility {
                code: 0,
                subtype: 0,
                reserved: [0; 3],
                body: body.clone(),
            },
            Icmpv4Message::ExtendedEchoRequest {
                code: 0,
                identifier: 1,
                sequence: 2,
                flags: extended_echo_flags::LOCAL,
                extensions: vec![0x20, 0, 0, 0, 0, 8, 3, 2, 0, 0, 0, 1],
            },
            Icmpv4Message::ExtendedEchoReply {
                code: extended_echo_reply_code::NO_ERROR,
                identifier: 1,
                sequence: 2,
                flags: extended_echo_flags::ACTIVE | extended_echo_flags::IPV4,
                extensions: vec![],
            },
            Icmpv4Message::from_parts(44, 0, &body).unwrap(),
        ] {
            round_trip(msg);
        }
    }

    #[test]
    fn every_assigned_type_has_a_variant() {
        for typ in 0..=255u8 {
            let mut bytes = vec![typ, 0, 0, 0];
            bytes.resize(20, 0);
            // Fixed-length types parse at exactly their length.
            let parsed = (4..=bytes.len())
                .find_map(|n| Icmpv4Message::parse(&bytes[..n]).ok())
                .unwrap();
            assert_eq!(parsed.typ(), typ);
            assert_eq!(
                matches!(parsed, Icmpv4Message::Other(_)),
                !has_variant(typ),
                "type {}",
                typ
            );
        }
    }

    #[test]
    fn short_and_long_messages_are_errors() {
        assert_eq!(
            Icmpv4Message::parse(&[8, 0, 0]),
            Err(ParseError::TooShort {
                needed: 4,
                actual: 3
            })
        );
        assert_eq!(
            Icmpv4Message::parse(&[13, 0, 0, 0, 0, 1, 0, 2]),
            Err(ParseError::TooShort {
                needed: 20,
                actual: 8
            })
        );
        assert_eq!(
            Icmpv4Message::parse(&[15, 0, 0, 0, 0, 1, 0, 2, 0xAA]),
            Err(ParseError::TrailingBytes {
                expected: 8,
                actual: 9
            })
        );
    }

    #[test]
    fn from_parts_uses_the_type_variant() {
        assert_eq!(
            Icmpv4Message::from_parts(8, 0, &[0, 1, 0, 2]),
            Ok(Icmpv4Message::echo_request(1, 2, vec![]))
        );
        assert!(matches!(
            Icmpv4Message::from_parts(44, 0, &[1, 2]),
            Ok(Icmpv4Message::Other(o)) if o.typ() == 44 && o.body() == [1, 2]
        ));
        assert!(Icmpv4Message::from_parts(8, 0, &[0]).is_err());
    }

    #[test]
    fn rest_field_accessors() {
        let mut original = vec![0; 8];
        original.extend([0x20, 0, 0, 0]);
        let msg = Icmpv4Message::DestinationUnreachable {
            code: unreachable_code::FRAGMENTATION_NEEDED,
            rest: [0, 2, 0x05, 0xdc],
            original,
        };
        assert_eq!(msg.next_hop_mtu(), Some(1500));
        assert_eq!(msg.extension_length(), Some(8));
        assert_eq!(msg.extensions(), Some(&[0x20, 0, 0, 0][..]));
        assert_eq!(
            Icmpv4Message::echo_request(1, 1, vec![]).next_hop_mtu(),
            None
        );
    }

    #[test]
    fn router_addresses_reads_the_entries() {
        let msg = Icmpv4Message::RouterAdvertisement {
            code: 0,
            num_addrs: 2,
            addr_entry_size: 2,
            lifetime: 1800,
            body: vec![10, 0, 0, 1, 0, 0, 0, 5, 10, 0, 0, 2, 0xff, 0xff, 0xff, 0xff],
        };
        assert_eq!(
            msg.router_addresses().unwrap(),
            vec![
                RouterAddress {
                    address: Ipv4Addr::new(10, 0, 0, 1),
                    preference: 5
                },
                RouterAddress {
                    address: Ipv4Addr::new(10, 0, 0, 2),
                    preference: -1
                },
            ]
        );
    }
}
