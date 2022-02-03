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
//! Packet parsing and construction.
//!
//! Where possible we use traits to support a common API for constructing the
//! ICMPv4 and ICMPv6 versions of the packets.
//!
//! Both packet types can be constructed from a slice: `&[u8]` via the [`TryFrom`] trait.
//!
//! # Examples
//!
//! Constructing an ICMPv4 echo request.
//! ```
//! # use icmp_socket::packet::*;
//! let packet = Icmpv4Packet::with_echo_request(
//!     42, // An identifier so you can recognize responses to your own packets.
//!     0, // the first echo request packet in our sequence.
//!     "a payload big enough to matter".as_bytes().to_vec()
//! ).unwrap();
//! ```
//!
//! Parsing an ICMPv4 packet from a byte buffer.
//! ```
//! # use icmp_socket::packet::*;
//! use std::convert::TryFrom;
//! # let packet = Icmpv4Packet::with_echo_request(
//! #     42, // An identifier so you can recognize responses to your own packets.
//! #     0, // the first echo request packet in our sequence.
//! #     "a payload big enough to matter".as_bytes().to_vec()
//! # ).unwrap();
//! # let mut byte_buffer = vec![0; 20];
//! # byte_buffer.extend(packet.get_bytes(true)); // convert a packet to bytes with a checksum.
//! let parsed_packet = Icmpv4Packet::try_from(byte_buffer.as_slice()).unwrap();
//! ```
use std::convert::TryFrom;

use byteorder::{BigEndian, ByteOrder};
use std::net::Ipv6Addr;

fn ipv6_sum_words(ip: &Ipv6Addr) -> u32 {
    ip.segments().iter().map(|x| *x as u32).sum()
}

fn sum_big_endian_words(bs: &[u8]) -> u32 {
    if bs.len() == 0 {
        return 0;
    }

    let len = bs.len();
    let mut data = &bs[..];
    let mut sum = 0u32;
    // Iterate by word which is two bytes.
    while data.len() >= 2 {
        sum += BigEndian::read_u16(&data[0..2]) as u32;
        // remove the first two bytes now that we've already summed them
        data = &data[2..];
    }

    if (len % 2) != 0 {
        // If odd then checksum the last byte
        sum += (data[0] as u32) << 8;
    }
    return sum;
}

/// Construct a packet for the EchoRequest messages.
pub trait WithEchoRequest {
    type Packet;

    fn with_echo_request(
        identifier: u16,
        sequence: u16,
        payload: Vec<u8>,
    ) -> Result<Self::Packet, IcmpPacketBuildError>;
}

/// Construct a packet for Echo Reply messages.
/// This packet type is really only used for the ICMPv6 protocol.
pub trait WithEchoReply {
    type Packet;

    fn with_echo_reply(
        identifier: u16,
        sequence: u16,
        payload: Vec<u8>,
    ) -> Result<Self::Packet, IcmpPacketBuildError>;
}

/// Construct a packet for Destination Unreachable messages.
pub trait WithUnreachable {
    type Packet;

    fn with_unreachable(code: u8, packet: Vec<u8>) -> Result<Self::Packet, IcmpPacketBuildError>;
}

/// Construct a packet for Parameter Problem messages.
pub trait WithParameterProblem {
    type Packet;
    type Pointer;

    fn with_parameter_problem(
        code: u8,
        pointer: Self::Pointer,
        packet: Vec<u8>,
    ) -> Result<Self::Packet, IcmpPacketBuildError>;
}

/// Construct a packet for Time Exceeded messages.
pub trait WithTimeExceeded {
    type Packet;

    fn with_time_exceeded(code: u8, packet: Vec<u8>) -> Result<Self::Packet, IcmpPacketBuildError>;
}

/// The possible Icmpv6 Message types.
#[derive(Debug, PartialEq)]
pub enum Icmpv6Message {
    // NOTE(JWALL): All of the below integers should be parsed as big endian on the
    // wire.
    Unreachable {
        _unused: u32,
        invoking_packet: Vec<u8>,
    },
    PacketTooBig {
        mtu: u32,
        invoking_packet: Vec<u8>,
    },
    TimeExceeded {
        _unused: u32,
        invoking_packet: Vec<u8>,
    },
    ParameterProblem {
        pointer: u32,
        invoking_packet: Vec<u8>,
    },
    PrivateExperimental {
        padding: u32,
        payload: Vec<u8>,
    },
    EchoRequest {
        identifier: u16,
        sequence: u16,
        payload: Vec<u8>,
    },
    EchoReply {
        identifier: u16,
        sequence: u16,
        payload: Vec<u8>,
    },
}

use Icmpv6Message::{
    EchoReply, EchoRequest, PacketTooBig, ParameterProblem, PrivateExperimental, TimeExceeded,
    Unreachable,
};

impl Icmpv6Message {
    /// Get this Icmpv6Message serialized to bytes.
    pub fn get_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        match self {
            Unreachable {
                _unused: field1,
                invoking_packet: field2,
            }
            | PacketTooBig {
                mtu: field1,
                invoking_packet: field2,
            }
            | TimeExceeded {
                _unused: field1,
                invoking_packet: field2,
            }
            | ParameterProblem {
                pointer: field1,
                invoking_packet: field2,
            }
            | PrivateExperimental {
                padding: field1,
                payload: field2,
            } => {
                let mut buf = vec![0; 4];
                BigEndian::write_u32(&mut buf, *field1);
                bytes.append(&mut buf);
                bytes.extend_from_slice(field2);
            }
            EchoRequest {
                identifier,
                sequence,
                payload,
            }
            | EchoReply {
                identifier,
                sequence,
                payload,
            } => {
                let mut buf = vec![0; 2];
                BigEndian::write_u16(&mut buf, *identifier);
                bytes.append(&mut buf);
                buf.resize(2, 0);
                BigEndian::write_u16(&mut buf, *sequence);
                bytes.append(&mut buf);
                bytes.extend_from_slice(payload);
            }
        }
        bytes
    }
}

#[derive(Debug)]
pub struct Icmpv6Packet {
    // NOTE(JWALL): All of the below integers should be parsed as big endian on the
    // wire.
    pub typ: u8,
    pub code: u8,
    pub checksum: u16,
    pub message: Icmpv6Message,
}

/// Error type returned by parsing the ICMP packets.
#[derive(Debug)]
pub enum PacketParseError {
    /// Not enough bytes to properly parse the packet from.
    PacketTooSmall(usize),
    /// An unrecognized ICMP type.
    UnrecognizedICMPType(u8),
}

impl Icmpv6Packet {
    /// Construct a packet by parsing the provided bytes.
    pub fn parse<B: AsRef<[u8]>>(bytes: B) -> Result<Self, PacketParseError> {
        let bytes = bytes.as_ref();
        // NOTE(jwall): All ICMP packets are at least 8 bytes long.
        if bytes.len() < 8 {
            return Err(PacketParseError::PacketTooSmall(bytes.len()));
        }
        let (typ, code, checksum) = (bytes[0], bytes[1], BigEndian::read_u16(&bytes[2..4]));
        let next_field = BigEndian::read_u32(&bytes[4..8]);
        let payload = bytes[8..].to_owned();
        let message = match typ {
            1 => Unreachable {
                _unused: next_field,
                invoking_packet: payload,
            },
            2 => PacketTooBig {
                mtu: next_field,
                invoking_packet: payload,
            },
            3 => TimeExceeded {
                _unused: next_field,
                invoking_packet: payload,
            },
            4 => ParameterProblem {
                pointer: next_field,
                invoking_packet: payload,
            },
            100 | 101 | 200 | 201 => PrivateExperimental {
                padding: next_field,
                payload: payload,
            },
            128 => EchoRequest {
                identifier: BigEndian::read_u16(&bytes[4..6]),
                sequence: BigEndian::read_u16(&bytes[6..8]),
                payload: payload,
            },
            129 => EchoReply {
                identifier: BigEndian::read_u16(&bytes[4..6]),
                sequence: BigEndian::read_u16(&bytes[6..8]),
                payload: payload,
            },
            t => return Err(PacketParseError::UnrecognizedICMPType(t)),
        };
        return Ok(Icmpv6Packet {
            typ: typ,
            code: code,
            checksum: checksum,
            message: message,
        });
    }

    /// Get this packet serialized to bytes suitable for sending on the wire.
    pub fn get_bytes(&self, with_checksum: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.typ);
        bytes.push(self.code);
        let mut buf = Vec::with_capacity(2);
        buf.resize(2, 0);
        BigEndian::write_u16(&mut buf, if with_checksum { self.checksum } else { 0 });
        bytes.append(&mut buf);
        bytes.append(&mut self.message.get_bytes());
        return bytes;
    }

    /// Calculate the checksum for the packet given the provided source and destination
    /// addresses.
    pub fn calculate_checksum(&self, source: &Ipv6Addr, dest: &Ipv6Addr) -> u16 {
        // First sum the pseudo header
        let mut sum = 0u32;
        sum += ipv6_sum_words(source);
        sum += ipv6_sum_words(dest);
        // according to rfc4443: https://tools.ietf.org/html/rfc4443#section-2.3
        // the ip next header value is 58
        sum += 58;

        // Then sum the len of the message bytes and then the message bytes starting
        // with the message type field and with the checksum field set to 0.
        let bytes = self.get_bytes(false);
        let len = bytes.len();
        sum += len as u32;
        sum += sum_big_endian_words(&bytes);

        // handle the carry
        while sum >> 16 != 0 {
            sum = (sum >> 16) + (sum & 0xFFFF);
        }
        !sum as u16
    }

    /// Fill the checksum for the packet using the given source and destination
    /// addresses.
    pub fn with_checksum(mut self, source: &Ipv6Addr, dest: &Ipv6Addr) -> Self {
        self.checksum = self.calculate_checksum(source, dest);
        self
    }

    /// Construct a packet for Packet Too Big messages.
    pub fn with_packet_too_big(mtu: u32, packet: Vec<u8>) -> Result<Self, IcmpPacketBuildError> {
        Ok(Self {
            typ: 2,
            code: 0,
            checksum: 0,
            // TODO(jwall): Should we enforce that the packet isn't too big?
            // It is not supposed to be larger than the minimum IPv6 MTU
            message: PacketTooBig {
                mtu: mtu,
                invoking_packet: packet,
            },
        })
    }
}

impl WithEchoRequest for Icmpv6Packet {
    type Packet = Icmpv6Packet;

    fn with_echo_request(
        identifier: u16,
        sequence: u16,
        payload: Vec<u8>,
    ) -> Result<Self::Packet, IcmpPacketBuildError> {
        Ok(Self {
            typ: 128,
            code: 0,
            checksum: 0,
            message: EchoRequest {
                identifier: identifier,
                sequence: sequence,
                payload: payload,
            },
        })
    }
}

impl WithEchoReply for Icmpv6Packet {
    type Packet = Icmpv6Packet;

    fn with_echo_reply(
        identifier: u16,
        sequence: u16,
        payload: Vec<u8>,
    ) -> Result<Self, IcmpPacketBuildError> {
        Ok(Self {
            typ: 129,
            code: 0,
            checksum: 0,
            message: EchoReply {
                identifier: identifier,
                sequence: sequence,
                payload: payload,
            },
        })
    }
}

impl WithUnreachable for Icmpv6Packet {
    type Packet = Icmpv6Packet;

    fn with_unreachable(code: u8, packet: Vec<u8>) -> Result<Self, IcmpPacketBuildError> {
        if code > 6 {
            return Err(IcmpPacketBuildError::InvalidCode(code));
        }
        Ok(Self {
            typ: 1,
            code: code,
            checksum: 0,
            // TODO(jwall): Should we enforce that the packet isn't too big?
            // It is not supposed to be larger than the minimum IPv6 MTU
            message: Unreachable {
                _unused: 0,
                invoking_packet: packet,
            },
        })
    }
}

impl WithParameterProblem for Icmpv6Packet {
    type Packet = Icmpv6Packet;
    type Pointer = u32;

    fn with_parameter_problem(
        code: u8,
        pointer: Self::Pointer,
        packet: Vec<u8>,
    ) -> Result<Self, IcmpPacketBuildError> {
        if code > 1 {
            return Err(IcmpPacketBuildError::InvalidCode(code));
        }
        Ok(Self {
            typ: 4,
            code: code,
            checksum: 0,
            message: ParameterProblem {
                pointer: pointer,
                invoking_packet: packet,
            },
        })
    }
}

impl WithTimeExceeded for Icmpv6Packet {
    type Packet = Icmpv6Packet;

    fn with_time_exceeded(code: u8, packet: Vec<u8>) -> Result<Self, IcmpPacketBuildError> {
        if code > 1 {
            return Err(IcmpPacketBuildError::InvalidCode(code));
        }
        Ok(Self {
            typ: 3,
            code: code,
            checksum: 0,
            // TODO(jwall): Should we enforce that the packet isn't too big?
            // It is not supposed to be larger than the minimum IPv6 MTU
            message: TimeExceeded {
                _unused: 0,
                invoking_packet: packet,
            },
        })
    }
}

impl TryFrom<&[u8]> for Icmpv6Packet {
    type Error = PacketParseError;
    fn try_from(b: &[u8]) -> Result<Self, Self::Error> {
        Icmpv6Packet::parse(b)
    }
}

/// Errors returned by constructors for a given packet.
#[derive(Debug, PartialEq)]
pub enum IcmpPacketBuildError {
    /// The code passed in for the payload was invalid for the message type.
    InvalidCode(u8),
}
use IcmpPacketBuildError::InvalidCode;

impl std::fmt::Display for IcmpPacketBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                InvalidCode(c) => format!("Invalid Code: {}", c),
            }
        )
    }
}

impl std::fmt::Display for PacketParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                PacketParseError::PacketTooSmall(c) => format!("Packet Too Small size: {}", c),
                PacketParseError::UnrecognizedICMPType(t) => format!("UnrecognizedIcmpType({})", t),
            }
        )
    }
}

impl From<IcmpPacketBuildError> for std::io::Error {
    fn from(err: IcmpPacketBuildError) -> Self {
        std::io::Error::new(std::io::ErrorKind::Other, format!("{}", err))
    }
}

impl From<PacketParseError> for std::io::Error {
    fn from(err: PacketParseError) -> Self {
        std::io::Error::new(std::io::ErrorKind::Other, format!("{}", err))
    }
}

/// The various messages for an Icmpv4 packet.
#[derive(Debug)]
pub enum Icmpv4Message {
    Unreachable {
        // type 3
        padding: u32,
        header: Vec<u8>,
    },
    TimeExceeded {
        // type 11
        padding: u32,
        header: Vec<u8>,
    },
    ParameterProblem {
        // type 12
        pointer: u8,
        padding: (u8, u16),
        header: Vec<u8>,
    },
    Quench {
        // type 4
        padding: u32,
        header: Vec<u8>,
    },
    Redirect {
        // type 5
        gateway: u32,
        header: Vec<u8>,
    },
    Echo {
        // type 8
        identifier: u16,
        sequence: u16,
        payload: Vec<u8>,
    },
    EchoReply {
        //  type 0
        identifier: u16,
        sequence: u16,
        payload: Vec<u8>,
    },
    Timestamp {
        // type 13
        identifier: u16,
        sequence: u16,
        originate: u32,
        receive: u32,
        transmit: u32,
    },
    TimestampReply {
        // type 14
        identifier: u16,
        sequence: u16,
        originate: u32,
        receive: u32,
        transmit: u32,
    },
    Information {
        // type 15
        identifier: u16,
        sequence: u16,
    },
    InformationReply {
        // type 16
        identifier: u16,
        sequence: u16,
    },
}

impl Icmpv4Message {
    /// Get this Icmpv4Message serialized as bytes.
    pub fn get_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(20);
        match self {
            Self::Unreachable {
                // type 3
                padding,
                header,
            }
            | Self::TimeExceeded {
                // type 11
                padding,
                header,
            }
            | Self::Quench {
                // type 4
                padding,
                header,
            }
            | Self::Redirect {
                // type 5
                gateway: padding,
                header,
            } => {
                let mut buf = vec![0; 4];
                BigEndian::write_u32(&mut buf, *padding);
                bytes.append(&mut buf);
                bytes.extend_from_slice(header);
            }
            Self::Echo {
                // type 8
                identifier,
                sequence,
                payload,
            }
            | Self::EchoReply {
                //  type 0
                identifier,
                sequence,
                payload,
            } => {
                let mut buf = vec![0; 2];
                BigEndian::write_u16(&mut buf, *identifier);
                bytes.append(&mut buf);
                buf.resize(2, 0);
                BigEndian::write_u16(&mut buf, *sequence);
                bytes.append(&mut buf);
                bytes.extend_from_slice(payload);
            }
            Self::ParameterProblem {
                // type 12
                pointer,
                padding,
                header,
            } => {
                bytes.push(*pointer);
                bytes.push(padding.0);
                let mut buf = vec![0, 2];
                BigEndian::write_u16(&mut buf, padding.1);
                bytes.append(&mut buf);
                bytes.extend_from_slice(header);
            }
            Self::Timestamp {
                // type 13
                identifier,
                sequence,
                originate,
                receive,
                transmit,
            }
            | Self::TimestampReply {
                // type 14
                identifier,
                sequence,
                originate,
                receive,
                transmit,
            } => {
                let mut buf = vec![0, 2];
                BigEndian::write_u16(&mut buf, *identifier);
                bytes.append(&mut buf);
                BigEndian::write_u16(&mut buf, *sequence);
                bytes.append(&mut buf);
                buf = vec![0, 4];
                BigEndian::write_u32(&mut buf, *originate);
                bytes.append(&mut buf);
                BigEndian::write_u32(&mut buf, *receive);
                bytes.append(&mut buf);
                BigEndian::write_u32(&mut buf, *transmit);
                bytes.append(&mut buf);
            }
            Self::Information {
                // type 15
                identifier,
                sequence,
            }
            | Self::InformationReply {
                // type 16
                identifier,
                sequence,
            } => {
                let mut buf = vec![0, 2];
                BigEndian::write_u16(&mut buf, *identifier);
                bytes.append(&mut buf);
                BigEndian::write_u16(&mut buf, *sequence);
                bytes.append(&mut buf);
            }
        }
        bytes
    }
}

/// An Icmpv4 Packet.
#[derive(Debug)]
pub struct Icmpv4Packet {
    pub typ: u8,
    pub code: u8,
    pub checksum: u16,
    pub message: Icmpv4Message,
}

impl Icmpv4Packet {
    /// Parse an Icmpv4Packet from bytes including the IPv4 header.
    pub fn parse<B: AsRef<[u8]>>(bytes: B) -> Result<Self, PacketParseError> {
        let mut bytes = bytes.as_ref();
        let mut packet_len = bytes.len();
        if bytes.len() < 28 {
            return Err(PacketParseError::PacketTooSmall(packet_len));
        }
        // NOTE(jwall) Because we use raw sockets the first 20 bytes are the IPv4 header.
        bytes = &bytes[20..];
        // NOTE(jwall): All ICMP packets are at least 8 bytes long.
        packet_len = bytes.len();
        let (typ, code, checksum) = (bytes[0], bytes[1], BigEndian::read_u16(&bytes[2..4]));
        let message = match typ {
            3 => Icmpv4Message::Unreachable {
                padding: BigEndian::read_u32(&bytes[4..8]),
                header: bytes[8..].to_owned(),
            },
            11 => Icmpv4Message::TimeExceeded {
                padding: BigEndian::read_u32(&bytes[4..8]),
                header: bytes[8..].to_owned(),
            },
            4 => Icmpv4Message::Quench {
                padding: BigEndian::read_u32(&bytes[4..8]),
                header: bytes[8..].to_owned(),
            },
            5 => Icmpv4Message::Redirect {
                gateway: BigEndian::read_u32(&bytes[4..8]),
                header: bytes[8..].to_owned(),
            },
            8 => Icmpv4Message::Echo {
                identifier: BigEndian::read_u16(&bytes[4..6]),
                sequence: BigEndian::read_u16(&bytes[6..8]),
                payload: bytes[8..].to_owned(),
            },
            0 => Icmpv4Message::EchoReply {
                identifier: BigEndian::read_u16(&bytes[4..6]),
                sequence: BigEndian::read_u16(&bytes[6..8]),
                payload: bytes[8..].to_owned(),
            },
            15 => Icmpv4Message::Information {
                identifier: BigEndian::read_u16(&bytes[4..6]),
                sequence: BigEndian::read_u16(&bytes[6..8]),
            },
            16 => Icmpv4Message::InformationReply {
                identifier: BigEndian::read_u16(&bytes[4..6]),
                sequence: BigEndian::read_u16(&bytes[6..8]),
            },
            13 => {
                if packet_len < 20 {
                    return Err(PacketParseError::PacketTooSmall(bytes.len()));
                }
                Icmpv4Message::Timestamp {
                    identifier: BigEndian::read_u16(&bytes[4..6]),
                    sequence: BigEndian::read_u16(&bytes[6..8]),
                    originate: BigEndian::read_u32(&bytes[8..12]),
                    receive: BigEndian::read_u32(&bytes[12..16]),
                    transmit: BigEndian::read_u32(&bytes[16..20]),
                }
            }
            14 => {
                if packet_len < 20 {
                    return Err(PacketParseError::PacketTooSmall(bytes.len()));
                }
                Icmpv4Message::TimestampReply {
                    identifier: BigEndian::read_u16(&bytes[4..6]),
                    sequence: BigEndian::read_u16(&bytes[6..8]),
                    originate: BigEndian::read_u32(&bytes[8..12]),
                    receive: BigEndian::read_u32(&bytes[12..16]),
                    transmit: BigEndian::read_u32(&bytes[16..20]),
                }
            }
            t => {
                dbg!(bytes);
                return Err(PacketParseError::UnrecognizedICMPType(t));
            }
        };
        return Ok(Icmpv4Packet {
            typ: typ,
            code: code,
            checksum: checksum,
            message: message,
        });
    }

    /// Get this packet serialized to bytes suitable for sending on the wire.
    pub fn get_bytes(&self, with_checksum: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.typ);
        bytes.push(self.code);
        let mut buf = vec![0; 2];
        BigEndian::write_u16(&mut buf, if with_checksum { self.checksum } else { 0 });
        bytes.append(&mut buf);
        bytes.append(&mut self.message.get_bytes());
        return bytes;
    }

    /// Calculate the checksum for the packet given the provided source and destination
    /// addresses.
    pub fn calculate_checksum(&self) -> u16 {
        // First sum the pseudo header
        let mut sum = 0u32;

        // Then sum the len of the message bytes and then the message bytes starting
        // with the message type field and with the checksum field set to 0.
        let bytes = self.get_bytes(false);
        sum += sum_big_endian_words(&bytes);

        // handle the carry
        while sum >> 16 != 0 {
            sum = (sum >> 16) + (sum & 0xFFFF);
        }
        !sum as u16
    }

    /// Populate the checksum field of this Packet.
    pub fn with_checksum(mut self) -> Self {
        self.checksum = self.calculate_checksum();
        self
    }
}

impl TryFrom<&[u8]> for Icmpv4Packet {
    type Error = PacketParseError;
    fn try_from(b: &[u8]) -> Result<Self, Self::Error> {
        Icmpv4Packet::parse(b)
    }
}

impl WithEchoRequest for Icmpv4Packet {
    type Packet = Icmpv4Packet;

    fn with_echo_request(
        identifier: u16,
        sequence: u16,
        payload: Vec<u8>,
    ) -> Result<Self::Packet, IcmpPacketBuildError> {
        Ok(Self {
            typ: 8,
            code: 0,
            checksum: 0,
            message: Icmpv4Message::Echo {
                identifier,
                sequence,
                payload,
            },
        })
    }
}

impl WithUnreachable for Icmpv4Packet {
    type Packet = Icmpv4Packet;

    fn with_unreachable(code: u8, packet: Vec<u8>) -> Result<Self::Packet, IcmpPacketBuildError> {
        if code > 5 {
            return Err(IcmpPacketBuildError::InvalidCode(code));
        }
        Ok(Self {
            typ: 3,
            code: code,
            checksum: 0,
            message: Icmpv4Message::Unreachable {
                padding: 0,
                header: packet,
            },
        })
    }
}

impl WithParameterProblem for Icmpv4Packet {
    type Packet = Icmpv4Packet;
    type Pointer = u8;

    fn with_parameter_problem(
        code: u8,
        pointer: Self::Pointer,
        packet: Vec<u8>,
    ) -> Result<Self::Packet, IcmpPacketBuildError> {
        if code != 0 {
            return Err(IcmpPacketBuildError::InvalidCode(code));
        }
        Ok(Self {
            typ: 12,
            code: code,
            checksum: 0,
            message: Icmpv4Message::ParameterProblem {
                pointer: pointer,
                padding: (0, 0),
                header: packet,
            },
        })
    }
}

impl WithTimeExceeded for Icmpv4Packet {
    type Packet = Icmpv4Packet;

    fn with_time_exceeded(code: u8, packet: Vec<u8>) -> Result<Self::Packet, IcmpPacketBuildError> {
        if code > 1 {
            return Err(IcmpPacketBuildError::InvalidCode(code));
        }
        Ok(Self {
            typ: 11,
            code: code,
            checksum: 0,
            message: Icmpv4Message::TimeExceeded {
                padding: 0,
                header: packet,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_construction_echo_request_test() {
        let pkt = Icmpv6Packet::with_echo_request(42, 1, vec![1, 2, 3, 4]).unwrap();
        assert_eq!(pkt.typ, 128);
        assert_eq!(pkt.code, 0);
        assert_eq!(
            pkt.message,
            EchoRequest {
                identifier: 42,
                sequence: 1,
                payload: vec![1, 2, 3, 4],
            }
        );
    }

    #[test]
    fn packet_construction_echo_reply_test() {
        let pkt = Icmpv6Packet::with_echo_reply(42, 1, vec![1, 2, 3, 4]).unwrap();
        assert_eq!(pkt.typ, 129);
        assert_eq!(pkt.code, 0);
        assert_eq!(
            pkt.message,
            EchoReply {
                identifier: 42,
                sequence: 1,
                payload: vec![1, 2, 3, 4],
            }
        );
    }

    #[test]
    fn packet_construction_too_big_test() {
        let pkt = Icmpv6Packet::with_packet_too_big(3, vec![1, 2, 3, 4]).unwrap();
        assert_eq!(pkt.typ, 2);
        assert_eq!(pkt.code, 0);
        assert_eq!(
            pkt.message,
            PacketTooBig {
                mtu: 3,
                invoking_packet: vec![1, 2, 3, 4],
            }
        );
    }

    #[test]
    fn packet_construction_time_exceeded() {
        let pkt = Icmpv6Packet::with_time_exceeded(0, vec![1, 2, 3, 4]).unwrap();
        assert_eq!(pkt.typ, 3);
        assert_eq!(pkt.code, 0);
        assert_eq!(
            pkt.message,
            TimeExceeded {
                _unused: 0,
                invoking_packet: vec![1, 2, 3, 4],
            }
        );
    }

    #[test]
    fn packet_construction_time_exceeded_invalid_code() {
        let pkt = Icmpv6Packet::with_time_exceeded(2, vec![1, 2, 3, 4]);
        assert!(pkt.is_err());
        let e = pkt.unwrap_err();
        assert_eq!(e, IcmpPacketBuildError::InvalidCode(2));
    }

    #[test]
    fn packet_construction_parameter_problem() {
        let pkt = Icmpv6Packet::with_parameter_problem(0, 30, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
            .unwrap();
        assert_eq!(pkt.typ, 4);
        assert_eq!(pkt.code, 0);
        assert_eq!(
            pkt.message,
            ParameterProblem {
                pointer: 30,
                invoking_packet: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            }
        );
    }

    #[test]
    fn packet_construction_parameter_problem_invalid_code() {
        let pkt = Icmpv6Packet::with_parameter_problem(3, 30, vec![1, 2, 3, 4]);
        assert!(pkt.is_err());
        let e = pkt.unwrap_err();
        assert_eq!(e, IcmpPacketBuildError::InvalidCode(3));
    }

    #[test]
    fn echo_packet_parse_test() {
        // NOTE(jwall): I am shamelessly ripping ff the cases for this from libpnet
        // The equivalent of your typical ping -6 ::1%lo
        let lo = &Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
        let mut data = vec![
            0x80, // Icmpv6 Type
            0x00, // Code
            0xff, 0xff, // Checksum
            0x00, 0x00, // Id
            0x00, 0x01, // Sequence
            // 56 bytes of "random" data
            0x20, 0x20, 0x75, 0x73, 0x74, 0x20, 0x61, 0x20, 0x66, 0x6c, 0x65, 0x73, 0x68, 0x20,
            0x77, 0x6f, 0x75, 0x6e, 0x64, 0x20, 0x20, 0x74, 0x69, 0x73, 0x20, 0x62, 0x75, 0x74,
            0x20, 0x61, 0x20, 0x73, 0x63, 0x72, 0x61, 0x74, 0x63, 0x68, 0x20, 0x20, 0x6b, 0x6e,
            0x69, 0x67, 0x68, 0x74, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x6e, 0x69, 0x20, 0x20, 0x20,
        ];
        let mut pkt = Icmpv6Packet::parse(&data).unwrap();
        assert_eq!(pkt.typ, 128);
        assert_eq!(pkt.code, 0x00);
        if let EchoRequest {
            identifier,
            sequence,
            payload,
        } = &pkt.message
        {
            assert_eq!(*identifier, 0);
            assert_eq!(*sequence, 1);
            assert_eq!(
                payload,
                &[
                    0x20, 0x20, 0x75, 0x73, 0x74, 0x20, 0x61, 0x20, 0x66, 0x6c, 0x65, 0x73, 0x68,
                    0x20, 0x77, 0x6f, 0x75, 0x6e, 0x64, 0x20, 0x20, 0x74, 0x69, 0x73, 0x20, 0x62,
                    0x75, 0x74, 0x20, 0x61, 0x20, 0x73, 0x63, 0x72, 0x61, 0x74, 0x63, 0x68, 0x20,
                    0x20, 0x6b, 0x6e, 0x69, 0x67, 0x68, 0x74, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x6e,
                    0x69, 0x20, 0x20, 0x20
                ]
            );
        } else {
            assert!(
                false,
                "Packet did not parse as an EchoRequest {:?}",
                pkt.message
            );
        }
        assert_eq!(pkt.get_bytes(true), data);
        assert_eq!(pkt.calculate_checksum(lo, lo), 0x1d2e);
        pkt = pkt.with_checksum(lo, lo);
        assert_eq!(pkt.checksum, 0x1d2e);

        // Check echo response as well
        data[0] = 0x81;
        let pkt = Icmpv6Packet::parse(&data).unwrap();
        assert_eq!(pkt.typ, 129);
        assert_eq!(pkt.code, 0);
        if let EchoReply {
            identifier,
            sequence,
            payload,
        } = &pkt.message
        {
            assert_eq!(*identifier, 0);
            assert_eq!(*sequence, 1);
            assert_eq!(
                payload,
                &[
                    0x20, 0x20, 0x75, 0x73, 0x74, 0x20, 0x61, 0x20, 0x66, 0x6c, 0x65, 0x73, 0x68,
                    0x20, 0x77, 0x6f, 0x75, 0x6e, 0x64, 0x20, 0x20, 0x74, 0x69, 0x73, 0x20, 0x62,
                    0x75, 0x74, 0x20, 0x61, 0x20, 0x73, 0x63, 0x72, 0x61, 0x74, 0x63, 0x68, 0x20,
                    0x20, 0x6b, 0x6e, 0x69, 0x67, 0x68, 0x74, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x6e,
                    0x69, 0x20, 0x20, 0x20
                ]
            );
        } else {
            assert!(
                false,
                "Packet did not parse as an EchoReply {:?}",
                pkt.message
            );
        }
        assert_eq!(pkt.get_bytes(true), data);
        assert_eq!(pkt.calculate_checksum(lo, lo), 0x1c2e);
    }
}
