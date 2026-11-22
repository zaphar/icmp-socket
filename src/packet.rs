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
//! # byte_buffer[0] = 0x45; // IPv4 version with a 5 word (20 byte) header.
//! # byte_buffer.extend(packet.get_bytes(true)); // convert a packet to bytes with a checksum.
//! let parsed_packet = Icmpv4Packet::try_from(byte_buffer.as_slice()).unwrap();
//! ```
use std::convert::TryFrom;

use byteorder::{BigEndian, ByteOrder};
use std::net::Ipv6Addr;

fn ipv6_sum_words(ip: &Ipv6Addr) -> u64 {
    ip.segments().iter().map(|x| *x as u64).sum()
}

// The sum is a u64 so that no input slice a caller can pass overflows it.
fn sum_big_endian_words(bs: &[u8]) -> u64 {
    if bs.len() == 0 {
        return 0;
    }

    let len = bs.len();
    let mut data = &bs[..];
    let mut sum = 0u64;
    // Iterate by word which is two bytes.
    while data.len() >= 2 {
        sum += BigEndian::read_u16(&data[0..2]) as u64;
        // remove the first two bytes now that we've already summed them
        data = &data[2..];
    }

    if (len % 2) != 0 {
        // If odd then checksum the last byte
        sum += (data[0] as u64) << 8;
    }
    return sum;
}

/// Fold the carries of a one's complement sum into 16 bits.
fn fold_carries(mut sum: u64) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }
    sum as u16
}

/// The ICMPv6 pseudo-header sum (RFC 4443 section 2.3) for a message of
/// `len` bytes.
fn ipv6_pseudo_header_sum(source: &Ipv6Addr, dest: &Ipv6Addr, len: usize) -> u64 {
    // 58 is the IPv6 next header value for ICMPv6.
    ipv6_sum_words(source) + ipv6_sum_words(dest) + len as u64 + 58
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
        // Sum the pseudo header, then the message bytes starting with the
        // type field and with the checksum field set to 0.
        let bytes = self.get_bytes(false);
        let sum = ipv6_pseudo_header_sum(source, dest, bytes.len()) + sum_big_endian_words(&bytes);
        !fold_carries(sum)
    }

    /// Fill the checksum for the packet using the given source and destination
    /// addresses.
    pub fn with_checksum(mut self, source: &Ipv6Addr, dest: &Ipv6Addr) -> Self {
        self.checksum = self.calculate_checksum(source, dest);
        self
    }

    /// Verify the packet's checksum against the given source and destination
    /// addresses. An ICMPv6 checksum covers the IPv6 pseudo-header, so both
    /// addresses are required: `dest` is the address the packet was received on
    /// and `source` is the address it came from.
    ///
    /// This serializes the parsed packet again, so it is only as exact as the
    /// parser. To verify bytes exactly as received, use
    /// [`Self::verify_checksum_bytes`].
    pub fn verify_checksum(&self, source: &Ipv6Addr, dest: &Ipv6Addr) -> bool {
        self.calculate_checksum(source, dest) == self.checksum
    }

    /// Verify the checksum of an ICMPv6 message as received. `bytes` begins at
    /// the ICMPv6 type byte. `source` and `dest` are the IPv6 addresses of the
    /// pseudo-header, as for [`Self::verify_checksum`].
    pub fn verify_checksum_bytes(bytes: &[u8], source: &Ipv6Addr, dest: &Ipv6Addr) -> bool {
        bytes.len() >= 4
            && fold_carries(
                ipv6_pseudo_header_sum(source, dest, bytes.len()) + sum_big_endian_words(bytes),
            ) == 0xFFFF
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

impl std::error::Error for IcmpPacketBuildError {}

impl std::error::Error for PacketParseError {}

/// The original error is kept inside the `io::Error`. Recover it with
/// `get_ref()` and `downcast_ref::<IcmpPacketBuildError>()`.
impl From<IcmpPacketBuildError> for std::io::Error {
    fn from(err: IcmpPacketBuildError) -> Self {
        std::io::Error::new(std::io::ErrorKind::Other, err)
    }
}

/// The original error is kept inside the `io::Error`. Recover it with
/// `get_ref()` and `downcast_ref::<PacketParseError>()`.
impl From<PacketParseError> for std::io::Error {
    fn from(err: PacketParseError) -> Self {
        std::io::Error::new(std::io::ErrorKind::Other, err)
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
                bytes.extend_from_slice(&padding.1.to_be_bytes());
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
                bytes.extend_from_slice(&identifier.to_be_bytes());
                bytes.extend_from_slice(&sequence.to_be_bytes());
                bytes.extend_from_slice(&originate.to_be_bytes());
                bytes.extend_from_slice(&receive.to_be_bytes());
                bytes.extend_from_slice(&transmit.to_be_bytes());
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
                bytes.extend_from_slice(&identifier.to_be_bytes());
                bytes.extend_from_slice(&sequence.to_be_bytes());
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
    /// Parse an Icmpv4Packet from bytes including the IPv4 header, as delivered
    /// by a raw (SOCK_RAW) socket.
    pub fn parse<B: AsRef<[u8]>>(bytes: B) -> Result<Self, PacketParseError> {
        let bytes = bytes.as_ref();
        // NOTE(jwall): We need at least a minimal 20 byte IPv4 header before we
        // can even read the header length field.
        if bytes.len() < 20 {
            return Err(PacketParseError::PacketTooSmall(bytes.len()));
        }
        // NOTE(jwall): Because we use raw sockets the packet is prefixed with the
        // IPv4 header. Its length is variable and lives in the low nibble of the
        // first byte (the IHL field), counted in 32 bit words. Assuming a fixed
        // 20 bytes misparses any packet that carries IP options.
        let header_len = ((bytes[0] & 0x0F) as usize) * 4;
        // A valid IPv4 header is between 20 and 60 bytes, must fit within the
        // buffer, and must leave room for the 8 byte minimum ICMP message.
        if header_len < 20 || bytes.len() < header_len + 8 {
            return Err(PacketParseError::PacketTooSmall(bytes.len()));
        }
        Self::parse_icmp(&bytes[header_len..])
    }

    /// Parse an Icmpv4Packet from bytes that begin at the ICMP header with no
    /// preceding IPv4 header, as delivered by a datagram (SOCK_DGRAM) socket.
    pub fn parse_dgram<B: AsRef<[u8]>>(bytes: B) -> Result<Self, PacketParseError> {
        Self::parse_icmp(bytes.as_ref())
    }

    /// Parse an Icmpv4Packet, auto-detecting whether the bytes are prefixed
    /// with an IPv4 header.
    ///
    /// Whether the kernel includes the IPv4 header on receive is not a reliable
    /// function of the socket type: raw sockets always include it, Linux
    /// datagram (ping) sockets never do, and macOS datagram sockets do. Rather
    /// than assume, we inspect the first byte: a valid IPv4 header begins with
    /// version 4 and an IHL of at least 5 words (`0x45..=0x4F`). No IANA
    /// assigned ICMP type falls in that range, so a real ICMP message is never
    /// mistaken for an IPv4 header.
    pub fn parse_auto<B: AsRef<[u8]>>(bytes: B) -> Result<Self, PacketParseError> {
        let bytes = bytes.as_ref();
        if Self::has_ipv4_header(bytes) {
            Self::parse(bytes)
        } else {
            Self::parse_dgram(bytes)
        }
    }

    /// Whether these bytes begin with what looks like a valid IPv4 header:
    /// version 4 in the high nibble and an IHL of at least 5 in the low nibble
    /// (i.e. a first byte of `0x45..=0x4F`).
    fn has_ipv4_header(bytes: &[u8]) -> bool {
        match bytes.first() {
            Some(&b) => (b >> 4) == 4 && (b & 0x0F) >= 5,
            None => false,
        }
    }

    /// Parse the ICMP message from bytes starting at the ICMP type byte.
    fn parse_icmp(bytes: &[u8]) -> Result<Self, PacketParseError> {
        // NOTE(jwall): All ICMP packets are at least 8 bytes long.
        let packet_len = bytes.len();
        if packet_len < 8 {
            return Err(PacketParseError::PacketTooSmall(packet_len));
        }
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
            12 => Icmpv4Message::ParameterProblem {
                pointer: bytes[4],
                padding: (bytes[5], BigEndian::read_u16(&bytes[6..8])),
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
        // Sum the message bytes starting with the type field and with the
        // checksum field set to 0.
        let bytes = self.get_bytes(false);
        !fold_carries(sum_big_endian_words(&bytes))
    }

    /// Populate the checksum field of this Packet.
    pub fn with_checksum(mut self) -> Self {
        self.checksum = self.calculate_checksum();
        self
    }

    /// Verify the packet's checksum. Returns true when the stored checksum
    /// matches the one computed over the message. An ICMPv4 checksum covers only
    /// the ICMP message, so no addresses are needed.
    ///
    /// This serializes the parsed packet again, so it is only as exact as the
    /// parser: the Timestamp and Information messages keep no bytes after
    /// their fixed fields, so a received message with extra bytes fails. To
    /// verify bytes exactly as received, use [`Self::verify_checksum_bytes`].
    pub fn verify_checksum(&self) -> bool {
        self.calculate_checksum() == self.checksum
    }

    /// Verify the checksum of an ICMPv4 message as received. `bytes` begins at
    /// the ICMP type byte, with no IPv4 header.
    pub fn verify_checksum_bytes(bytes: &[u8]) -> bool {
        bytes.len() >= 4 && fold_carries(sum_big_endian_words(bytes)) == 0xFFFF
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

impl WithEchoReply for Icmpv4Packet {
    type Packet = Icmpv4Packet;

    fn with_echo_reply(
        identifier: u16,
        sequence: u16,
        payload: Vec<u8>,
    ) -> Result<Self::Packet, IcmpPacketBuildError> {
        Ok(Self {
            typ: 0,
            code: 0,
            checksum: 0,
            message: Icmpv4Message::EchoReply {
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

    #[test]
    fn icmpv4_parse_respects_variable_ihl() {
        // A minimal ICMP EchoReply (type 0): identifier=42, sequence=1, payload=[1,2,3,4].
        let icmp = [
            0x00, 0x00, // type, code
            0x00, 0x00, // checksum
            0x00, 0x2a, // identifier = 42
            0x00, 0x01, // sequence = 1
            0x01, 0x02, 0x03, 0x04, // payload
        ];
        // Build a raw buffer prefixed with an IPv4 header of the given IHL
        // (header length in 32 bit words). The header contents past the first
        // byte are irrelevant to the parser.
        let build = |ihl: u8| {
            let mut buf = vec![0u8; (ihl as usize) * 4];
            buf[0] = 0x40 | ihl; // version 4, given IHL
            buf.extend_from_slice(&icmp);
            buf
        };
        // IHL 5 is the common no-options case; 6..=8 exercise IP options.
        for ihl in 5..=8u8 {
            let pkt = Icmpv4Packet::parse(&build(ihl))
                .unwrap_or_else(|e| panic!("IHL {} failed to parse: {:?}", ihl, e));
            assert_eq!(pkt.typ, 0);
            assert_eq!(pkt.code, 0);
            if let Icmpv4Message::EchoReply {
                identifier,
                sequence,
                payload,
            } = pkt.message
            {
                assert_eq!(identifier, 42);
                assert_eq!(sequence, 1);
                assert_eq!(payload, vec![1, 2, 3, 4]);
            } else {
                panic!("IHL {} did not parse as EchoReply: {:?}", ihl, pkt.message);
            }
        }
    }

    #[test]
    fn icmpv4_parse_rejects_short_header() {
        // An IHL of 4 words (16 bytes) is below the 20 byte IPv4 minimum, even
        // though the buffer itself is long enough to look plausible.
        let mut buf = vec![0u8; 16 + 12];
        buf[0] = 0x44;
        assert!(matches!(
            Icmpv4Packet::parse(&buf),
            Err(PacketParseError::PacketTooSmall(_))
        ));
    }

    #[test]
    fn icmpv4_parse_dgram_has_no_ip_header() {
        // Datagram (SOCK_DGRAM) sockets deliver the ICMP message with no IPv4
        // header, so parse_dgram must not strip anything.
        let icmp = [
            0x00, 0x00, // type, code
            0x00, 0x00, // checksum
            0x00, 0x2a, // identifier = 42
            0x00, 0x01, // sequence = 1
            0x01, 0x02, 0x03, 0x04, // payload
        ];
        let pkt = Icmpv4Packet::parse_dgram(&icmp).unwrap();
        assert_eq!(pkt.typ, 0);
        if let Icmpv4Message::EchoReply {
            identifier,
            sequence,
            payload,
        } = pkt.message
        {
            assert_eq!(identifier, 42);
            assert_eq!(sequence, 1);
            assert_eq!(payload, vec![1, 2, 3, 4]);
        } else {
            panic!("did not parse as EchoReply: {:?}", pkt.message);
        }
        // The raw parser strips a (here nonexistent) IPv4 header, so the same
        // header-less bytes must not parse cleanly as if they were raw.
        assert!(Icmpv4Packet::parse(&icmp).is_err());
    }

    #[test]
    fn icmpv4_parse_auto_detects_header() {
        let icmp = [
            0x00, 0x00, // type, code
            0x00, 0x00, // checksum
            0x00, 0x2a, // identifier = 42
            0x00, 0x01, // sequence = 1
            0x01, 0x02, 0x03, 0x04, // payload
        ];

        let check = |pkt: Icmpv4Packet| {
            assert_eq!(pkt.typ, 0);
            if let Icmpv4Message::EchoReply {
                identifier,
                sequence,
                ..
            } = pkt.message
            {
                assert_eq!(identifier, 42);
                assert_eq!(sequence, 1);
            } else {
                panic!("did not parse as EchoReply: {:?}", pkt.message);
            }
        };

        // Header-less bytes (Linux dgram): parsed directly.
        check(Icmpv4Packet::parse_auto(&icmp).unwrap());

        // With a 20 byte IPv4 header (raw, or macOS dgram): header detected and
        // stripped.
        let mut with_header = vec![0u8; 20];
        with_header[0] = 0x45;
        with_header.extend_from_slice(&icmp);
        check(Icmpv4Packet::parse_auto(&with_header).unwrap());

        // With a 24 byte IPv4 header carrying options (IHL 6): still detected.
        let mut with_options = vec![0u8; 24];
        with_options[0] = 0x46;
        with_options.extend_from_slice(&icmp);
        check(Icmpv4Packet::parse_auto(&with_options).unwrap());
    }

    #[test]
    fn icmpv4_verify_checksum() {
        let good = Icmpv4Packet::with_echo_request(42, 1, vec![1, 2, 3, 4])
            .unwrap()
            .with_checksum();
        assert!(good.verify_checksum());

        // A wrong checksum must not verify.
        let mut bad = Icmpv4Packet::with_echo_request(42, 1, vec![1, 2, 3, 4])
            .unwrap()
            .with_checksum();
        bad.checksum ^= 0xFFFF;
        assert!(!bad.verify_checksum());
    }

    #[test]
    fn icmpv6_verify_checksum() {
        let lo = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
        let good = Icmpv6Packet::with_echo_request(42, 1, vec![1, 2, 3, 4])
            .unwrap()
            .with_checksum(&lo, &lo);
        assert!(good.verify_checksum(&lo, &lo));

        // A wrong checksum must not verify.
        let mut bad = good;
        bad.checksum ^= 0xFFFF;
        assert!(!bad.verify_checksum(&lo, &lo));
    }

    #[test]
    fn icmpv4_timestamp_and_information_round_trip() {
        // Each message is serialized back to exactly the bytes it was parsed
        // from. These four types once panicked in get_bytes.
        let timestamp_body: Vec<u8> = (1..=12).collect();
        for typ in [13u8, 14] {
            let mut raw = vec![typ, 0, 0, 0, 0x12, 0x34, 0x56, 0x78];
            raw.extend_from_slice(&timestamp_body);
            let pkt = Icmpv4Packet::parse_dgram(&raw).unwrap();
            assert_eq!(pkt.get_bytes(true), raw, "type {}", typ);
            pkt.with_checksum().verify_checksum();
        }
        for typ in [15u8, 16] {
            let raw = vec![typ, 0, 0, 0, 0x12, 0x34, 0x56, 0x78];
            let pkt = Icmpv4Packet::parse_dgram(&raw).unwrap();
            assert_eq!(pkt.get_bytes(true), raw, "type {}", typ);
            pkt.with_checksum().verify_checksum();
        }
    }

    #[test]
    fn icmpv4_parameter_problem_round_trip() {
        let pkt = Icmpv4Packet::with_parameter_problem(0, 9, vec![0x45, 0, 0, 20])
            .unwrap()
            .with_checksum();
        let bytes = pkt.get_bytes(true);
        let parsed = Icmpv4Packet::parse_dgram(&bytes).unwrap();
        assert_eq!(parsed.typ, 12);
        assert_eq!(parsed.get_bytes(true), bytes);
        assert!(parsed.verify_checksum());
        match parsed.message {
            Icmpv4Message::ParameterProblem {
                pointer, header, ..
            } => {
                assert_eq!(pointer, 9);
                assert_eq!(header, vec![0x45, 0, 0, 20]);
            }
            m => panic!("expected ParameterProblem, got {:?}", m),
        }
    }

    #[test]
    fn icmpv4_echo_reply_construction() {
        let pkt = Icmpv4Packet::with_echo_reply(42, 1, vec![1, 2, 3, 4])
            .unwrap()
            .with_checksum();
        assert_eq!(pkt.typ, 0);
        assert_eq!(pkt.code, 0);
        let parsed = Icmpv4Packet::parse_dgram(pkt.get_bytes(true)).unwrap();
        assert!(parsed.verify_checksum());
        match parsed.message {
            Icmpv4Message::EchoReply {
                identifier,
                sequence,
                payload,
            } => {
                assert_eq!((identifier, sequence), (42, 1));
                assert_eq!(payload, vec![1, 2, 3, 4]);
            }
            m => panic!("expected EchoReply, got {:?}", m),
        }
    }

    #[test]
    fn packet_errors_survive_conversion_to_io_error() {
        let io: std::io::Error = PacketParseError::UnrecognizedICMPType(99).into();
        assert_eq!(io.to_string(), "UnrecognizedIcmpType(99)");
        match io
            .get_ref()
            .and_then(|e| e.downcast_ref::<PacketParseError>())
        {
            Some(PacketParseError::UnrecognizedICMPType(99)) => {}
            other => panic!("expected UnrecognizedICMPType(99), got {:?}", other),
        }

        let io: std::io::Error = IcmpPacketBuildError::InvalidCode(7).into();
        assert_eq!(
            io.get_ref()
                .and_then(|e| e.downcast_ref::<IcmpPacketBuildError>()),
            Some(&IcmpPacketBuildError::InvalidCode(7))
        );
    }

    #[test]
    fn icmpv4_verify_checksum_bytes() {
        let pkt = Icmpv4Packet::with_echo_request(42, 1, vec![1, 2, 3, 4, 5])
            .unwrap()
            .with_checksum();
        let mut bytes = pkt.get_bytes(true);
        assert!(Icmpv4Packet::verify_checksum_bytes(&bytes));
        bytes[8] ^= 0x01;
        assert!(!Icmpv4Packet::verify_checksum_bytes(&bytes));

        // An Information message with trailing bytes verifies from the raw
        // bytes, although the parsed packet keeps no trailing bytes.
        let mut raw = vec![15, 0, 0, 0, 0, 1, 0, 2, 0xAA, 0xBB];
        let cksum = !fold_carries(sum_big_endian_words(&raw));
        raw[2..4].copy_from_slice(&cksum.to_be_bytes());
        assert!(Icmpv4Packet::verify_checksum_bytes(&raw));
        assert!(!Icmpv4Packet::parse_dgram(&raw).unwrap().verify_checksum());
    }

    #[test]
    fn icmpv6_verify_checksum_bytes() {
        let lo = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
        let other = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let pkt = Icmpv6Packet::with_echo_request(42, 1, vec![1, 2, 3, 4, 5])
            .unwrap()
            .with_checksum(&lo, &lo);
        let bytes = pkt.get_bytes(true);
        assert!(Icmpv6Packet::verify_checksum_bytes(&bytes, &lo, &lo));
        assert!(!Icmpv6Packet::verify_checksum_bytes(&bytes, &other, &lo));
    }
}
