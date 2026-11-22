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
//! ICMPv4 messages (RFC 792 and later RFCs).
//!
//! An [`Icmpv4Message`] is one ICMP message without its IPv4 header.
//! [`Icmpv4Message::parse`] and [`Icmpv4Message::to_bytes`] are exact
//! inverses: every byte of a message is held in a field.
use std::net::Ipv4Addr;

use crate::checksum;
use crate::error::{ModelledTypeError, ParseError};
use crate::wire::{Reader, Writer, check_header};

/// ICMPv4 type numbers.
pub mod msg_type {
    pub const ECHO_REPLY: u8 = 0;
    pub const DESTINATION_UNREACHABLE: u8 = 3;
    pub const SOURCE_QUENCH: u8 = 4;
    pub const REDIRECT: u8 = 5;
    pub const ECHO_REQUEST: u8 = 8;
    pub const TIME_EXCEEDED: u8 = 11;
    pub const PARAMETER_PROBLEM: u8 = 12;
    pub const TIMESTAMP: u8 = 13;
    pub const TIMESTAMP_REPLY: u8 = 14;
    pub const INFORMATION_REQUEST: u8 = 15;
    pub const INFORMATION_REPLY: u8 = 16;
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
    /// [`Icmpv4Message::extension_length`]. `original` is the start of the
    /// datagram that caused the error.
    DestinationUnreachable {
        code: u8,
        rest: [u8; 4],
        original: Vec<u8>,
    },
    /// Type 4 (RFC 792). Deprecated by RFC 6918; still seen in the field.
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
    /// Type 8 (RFC 792).
    EchoRequest {
        code: u8,
        identifier: u16,
        sequence: u16,
        payload: Vec<u8>,
    },
    /// Type 11 (RFC 792). `rest` holds bytes 4..8; see
    /// [`Icmpv4Message::extension_length`].
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
    /// A type this crate does not model.
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
        ECHO_REPLY
            | DESTINATION_UNREACHABLE
            | SOURCE_QUENCH
            | REDIRECT
            | ECHO_REQUEST
            | TIME_EXCEEDED
            | PARAMETER_PROBLEM
            | TIMESTAMP
            | TIMESTAMP_REPLY
            | INFORMATION_REQUEST
            | INFORMATION_REPLY
    )
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

    /// The type number.
    pub fn typ(&self) -> u8 {
        use msg_type::*;
        match self {
            Self::EchoReply { .. } => ECHO_REPLY,
            Self::DestinationUnreachable { .. } => DESTINATION_UNREACHABLE,
            Self::SourceQuench { .. } => SOURCE_QUENCH,
            Self::Redirect { .. } => REDIRECT,
            Self::EchoRequest { .. } => ECHO_REQUEST,
            Self::TimeExceeded { .. } => TIME_EXCEEDED,
            Self::ParameterProblem { .. } => PARAMETER_PROBLEM,
            Self::Timestamp { .. } => TIMESTAMP,
            Self::TimestampReply { .. } => TIMESTAMP_REPLY,
            Self::InformationRequest { .. } => INFORMATION_REQUEST,
            Self::InformationReply { .. } => INFORMATION_REPLY,
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
            | Self::EchoRequest { code, .. }
            | Self::TimeExceeded { code, .. }
            | Self::ParameterProblem { code, .. }
            | Self::Timestamp { code, .. }
            | Self::TimestampReply { code, .. }
            | Self::InformationRequest { code, .. }
            | Self::InformationReply { code, .. } => *code,
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
    /// RFC 4884 extension objects after it, or `None` when the length field
    /// is 0 (no extensions) or the type has no such field.
    pub fn extension_length(&self) -> Option<usize> {
        let words = match self {
            Self::DestinationUnreachable { rest, .. } | Self::TimeExceeded { rest, .. } => rest[1],
            Self::ParameterProblem { rest, .. } => rest[0],
            _ => return None,
        };
        (words != 0).then_some(usize::from(words) * 4)
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
                let (identifier, sequence) = (r.u16()?, r.u16()?);
                let payload = r.rest();
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
            INFORMATION_REQUEST | INFORMATION_REPLY => {
                r.exactly(8)?;
                let (identifier, sequence) = (r.u16()?, r.u16()?);
                if typ == INFORMATION_REQUEST {
                    Self::InformationRequest {
                        code,
                        identifier,
                        sequence,
                    }
                } else {
                    Self::InformationReply {
                        code,
                        identifier,
                        sequence,
                    }
                }
            }
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
            } => {
                w.bytes(rest).bytes(original);
            }
            Self::Redirect {
                gateway, original, ..
            } => {
                w.ipv4(gateway).bytes(original);
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
            } => {
                w.u16(*identifier).u16(*sequence);
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

    fn round_trip(msg: Icmpv4Message) {
        let bytes = msg.to_bytes();
        assert!(Icmpv4Message::verify_checksum(&bytes), "{:?}", msg);
        assert_eq!(Icmpv4Message::parse(&bytes).unwrap(), msg);
    }

    #[test]
    fn every_variant_round_trips() {
        round_trip(Icmpv4Message::echo_request(42, 7, vec![1, 2, 3]));
        round_trip(Icmpv4Message::echo_reply(42, 7, vec![]));
        round_trip(Icmpv4Message::DestinationUnreachable {
            code: unreachable_code::FRAGMENTATION_NEEDED,
            rest: [0, 0, 0x05, 0xdc],
            original: vec![0x45, 0, 0, 20],
        });
        round_trip(Icmpv4Message::SourceQuench {
            code: 0,
            unused: [0; 4],
            original: vec![0x45],
        });
        round_trip(Icmpv4Message::Redirect {
            code: redirect_code::HOST,
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            original: vec![0x45, 1],
        });
        round_trip(Icmpv4Message::TimeExceeded {
            code: time_exceeded_code::TTL,
            rest: [0; 4],
            original: vec![0x45, 2],
        });
        round_trip(Icmpv4Message::ParameterProblem {
            code: parameter_problem_code::POINTER,
            pointer: 9,
            rest: [0; 3],
            original: vec![0x45, 3],
        });
        round_trip(Icmpv4Message::Timestamp {
            code: 0,
            identifier: 1,
            sequence: 2,
            originate: 3,
            receive: 4,
            transmit: 5,
        });
        round_trip(Icmpv4Message::TimestampReply {
            code: 0,
            identifier: 1,
            sequence: 2,
            originate: 3,
            receive: 4,
            transmit: 5,
        });
        round_trip(Icmpv4Message::InformationRequest {
            code: 0,
            identifier: 1,
            sequence: 2,
        });
        round_trip(Icmpv4Message::InformationReply {
            code: 0,
            identifier: 1,
            sequence: 2,
        });
        round_trip(Icmpv4Message::Other(
            Icmpv4Other::new(42, 0, vec![1, 2, 3, 4]).unwrap(),
        ));
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
    fn other_rejects_modelled_types() {
        assert_eq!(
            Icmpv4Other::new(8, 0, vec![]),
            Err(ModelledTypeError { typ: 8 })
        );
    }

    #[test]
    fn rest_field_accessors() {
        let msg = Icmpv4Message::DestinationUnreachable {
            code: unreachable_code::FRAGMENTATION_NEEDED,
            rest: [0, 2, 0x05, 0xdc],
            original: vec![],
        };
        assert_eq!(msg.next_hop_mtu(), Some(1500));
        assert_eq!(msg.extension_length(), Some(8));
        assert_eq!(
            Icmpv4Message::echo_request(1, 1, vec![]).next_hop_mtu(),
            None
        );
    }
}
