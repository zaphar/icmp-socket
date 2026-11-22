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
//! ICMPv6 messages (RFC 4443 and later RFCs).
//!
//! An [`Icmpv6Message`] is one ICMPv6 message without its IPv6 header.
//! [`Icmpv6Message::parse`] and [`Icmpv6Message::to_bytes`] are exact
//! inverses: every byte of a message is held in a field.
//!
//! The ICMPv6 checksum covers a pseudo-header with the source and
//! destination addresses, so the checksummed forms take both addresses. A
//! socket sends with [`Icmpv6Message::to_bytes_unchecksummed`]: the kernel
//! fills the checksum in (RFC 3542 section 3.1).
use std::net::Ipv6Addr;

use crate::checksum;
use crate::error::{ModelledTypeError, ParseError};
use crate::wire::{Reader, Writer, check_header};

/// ICMPv6 type numbers.
pub mod msg_type {
    pub const DESTINATION_UNREACHABLE: u8 = 1;
    pub const PACKET_TOO_BIG: u8 = 2;
    pub const TIME_EXCEEDED: u8 = 3;
    pub const PARAMETER_PROBLEM: u8 = 4;
    pub const ECHO_REQUEST: u8 = 128;
    pub const ECHO_REPLY: u8 = 129;
}

/// Destination Unreachable codes (RFC 4443, RFC 6554, RFC 8883).
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

/// An ICMPv6 message. The variant is the message type; [`Self::typ`]
/// returns its number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Icmpv6Message {
    /// Type 1 (RFC 4443). `rest` holds bytes 4..8; see
    /// [`Icmpv6Message::extension_length`]. `original` is the start of the
    /// packet that caused the error.
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
    /// [`Icmpv6Message::extension_length`].
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
    /// A type this crate does not model.
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
    use msg_type::*;
    matches!(
        typ,
        DESTINATION_UNREACHABLE
            | PACKET_TOO_BIG
            | TIME_EXCEEDED
            | PARAMETER_PROBLEM
            | ECHO_REQUEST
            | ECHO_REPLY
    )
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
            Self::Other(o) => o.typ,
        }
    }

    /// The code.
    pub fn code(&self) -> u8 {
        match self {
            Self::DestinationUnreachable { code, .. }
            | Self::PacketTooBig { code, .. }
            | Self::TimeExceeded { code, .. }
            | Self::ParameterProblem { code, .. }
            | Self::EchoRequest { code, .. }
            | Self::EchoReply { code, .. } => *code,
            Self::Other(o) => o.code,
        }
    }

    /// The length in bytes of the original packet when the message carries
    /// RFC 4884 extension objects after it, or `None` when the length field
    /// is 0 (no extensions) or the type has no such field.
    pub fn extension_length(&self) -> Option<usize> {
        match self {
            Self::DestinationUnreachable { rest, .. } | Self::TimeExceeded { rest, .. } => {
                // ICMPv6 counts the length in 64-bit words (RFC 4884).
                (rest[0] != 0).then_some(usize::from(rest[0]) * 8)
            }
            _ => None,
        }
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
                let rest = r.array()?;
                let original = r.rest();
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
                let (identifier, sequence) = (r.u16()?, r.u16()?);
                let payload = r.rest();
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
        round_trip(Icmpv6Message::echo_request(42, 7, vec![1, 2, 3]));
        round_trip(Icmpv6Message::echo_reply(42, 7, vec![]));
        round_trip(Icmpv6Message::DestinationUnreachable {
            code: unreachable_code::PORT,
            rest: [0; 4],
            original: vec![0x60, 0, 0, 0],
        });
        round_trip(Icmpv6Message::PacketTooBig {
            code: 0,
            mtu: 1280,
            original: vec![0x60],
        });
        round_trip(Icmpv6Message::TimeExceeded {
            code: time_exceeded_code::HOP_LIMIT,
            rest: [0; 4],
            original: vec![0x60, 1],
        });
        round_trip(Icmpv6Message::ParameterProblem {
            code: parameter_problem_code::UNRECOGNIZED_OPTION,
            pointer: 40,
            original: vec![0x60, 2],
        });
        round_trip(Icmpv6Message::Other(
            Icmpv6Other::new(200, 0, vec![1, 2, 3, 4]).unwrap(),
        ));
    }

    #[test]
    fn checksum_depends_on_the_addresses() {
        let other = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let bytes = Icmpv6Message::echo_request(1, 1, vec![9]).to_bytes(&LO, &LO);
        assert!(!Icmpv6Message::verify_checksum(&bytes, &other, &LO));
    }

    #[test]
    fn short_messages_are_errors() {
        assert_eq!(
            Icmpv6Message::parse(&[128, 0, 0, 0, 0]),
            Err(ParseError::TooShort {
                needed: 8,
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
}
