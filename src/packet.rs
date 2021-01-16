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
use std::net::Ipv6Addr;
use byteorder::{ByteOrder, BigEndian};

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

    if (len % 2) != 0 { // If odd then checksum the last byte
        sum += (data[0] as u32) << 8;
    }
    return sum;
}

#[derive(Debug)]
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
    }
}

use Icmpv6Message::{Unreachable, PacketTooBig, TimeExceeded, ParameterProblem, PrivateExperimental, EchoRequest, EchoReply};

impl Icmpv6Message {
    pub fn get_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        match self {
            Unreachable {_unused: field1, invoking_packet: field2 } |
            PacketTooBig {mtu: field1, invoking_packet: field2 } |
            TimeExceeded {_unused: field1, invoking_packet: field2 } |
            ParameterProblem {pointer: field1, invoking_packet: field2 } |
            PrivateExperimental {padding: field1, payload: field2 } => {
                let mut buf = vec![0; 4];
                BigEndian::write_u32(&mut buf, *field1);
                bytes.append(&mut buf);
                bytes.extend_from_slice(field2);
            },
            EchoRequest{
                identifier,
                sequence,
                payload,
            } | EchoReply{
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

#[derive(Debug)]
pub enum PacketParseError {
    PacketTooSmall(usize),
    UnrecognizedICMPType,
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
            1 => Unreachable{
                _unused: next_field,
                invoking_packet: payload,
            },
            2 => PacketTooBig{
                mtu: next_field,
                invoking_packet: payload,
            },
            3 => TimeExceeded{
                _unused: next_field,
                invoking_packet: payload,
            },
            4 => ParameterProblem {
                pointer: next_field,
                invoking_packet: payload,
            },
            100 | 101 | 200 | 201 =>  PrivateExperimental{
                padding: next_field,
                payload: payload, 
            },
            128 => EchoRequest{
                identifier: BigEndian::read_u16(&bytes[4..6]),
                sequence: BigEndian::read_u16(&bytes[6..8]),
                payload: payload,
            },
            129 => EchoReply{
                identifier: BigEndian::read_u16(&bytes[4..6]),
                sequence: BigEndian::read_u16(&bytes[6..8]),
                payload: payload,
            },
            _ => return Err(PacketParseError::UnrecognizedICMPType),
        };
        return Ok(Icmpv6Packet{
            typ: typ,
            code: code,
            checksum: checksum,
            message: message,
        })
    }

    /// Get this packet serialized to bytes suitable for sending on the wire.
    pub fn get_bytes(&self, with_checksum: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.typ);
        bytes.push(self.code);
        let mut buf = Vec::with_capacity(2);
        buf.resize(2, 0);
        BigEndian::write_u16(&mut buf, if with_checksum {
            self.checksum
        } else {
            0
        });
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

    /// Construct a packet for Destination Unreachable messages.
    pub fn with_unreachable(code: u8, packet: Vec<u8>) -> Result<Self, Icmpv6PacketBuildError> {
        if code > 6 {
            return Err(Icmpv6PacketBuildError::InvalidCode(code));
        }
        Ok(Self {
            typ: 1,
            code: code,
            checksum: 0,
            // TODO(jwall): Should we enforce that the packet isn't too big?
            // It is not supposed to be larger than the minimum IPv6 MTU
            message: Unreachable{
                _unused: 0,
                invoking_packet: packet,
            },
        })
    }
   
    /// Construct a packet for Packet Too Big messages.
    pub fn with_packet_too_big(mtu: u32, packet: Vec<u8>) -> Result<Self, Icmpv6PacketBuildError> {
        Ok(Self{
            typ: 2,
            code: 0,
            checksum: 0,
            // TODO(jwall): Should we enforce that the packet isn't too big?
            // It is not supposed to be larger than the minimum IPv6 MTU
            message: PacketTooBig{
                mtu: mtu,
                invoking_packet: packet,
            },
        })
    }
   
    /// Construct a packet for Time Exceeded messages.
    pub fn with_time_exceeded(code: u8, packet: Vec<u8>) -> Result<Self, Icmpv6PacketBuildError> {
        if code > 1 {
            return Err(Icmpv6PacketBuildError::InvalidCode(code));
        }
        Ok(Self{
            typ: 3,
            code: code,
            checksum: 0,
            // TODO(jwall): Should we enforce that the packet isn't too big?
            // It is not supposed to be larger than the minimum IPv6 MTU
            message: TimeExceeded{
                _unused: 0,
                invoking_packet: packet,
            },
        })
    }

    /// Construct a packet for Parameter Problem messages.
    pub fn with_parameter_problem(code: u8, pointer: u32, packet: Vec<u8>) -> Result<Self, Icmpv6PacketBuildError> {
        if code > 1 {
            return Err(Icmpv6PacketBuildError::InvalidCode(code));
        }
        Ok(Self {
            typ: 4,
            code: code,
            checksum: 0,
            message: ParameterProblem{
                pointer: pointer,
                invoking_packet: packet,
            }
        })
    }

    /// Construct a packet for Echo Request messages.
    pub fn with_echo_request(identifier: u16, sequence: u16, payload: Vec<u8>) -> Result<Self, Icmpv6PacketBuildError> {
        Ok(Self {
            typ: 4,
            code: 0,
            checksum: 0,
            message: EchoRequest{
                identifier: identifier,
                sequence: sequence,
                payload: payload,
            }
        })
    }

    /// Construct a packet for Echo Reply messages.
    pub fn with_echo_reply(identifier: u16, sequence: u16, payload: Vec<u8>) -> Result<Self, Icmpv6PacketBuildError> {
        Ok(Self {
            typ: 4,
            code: 0,
            checksum: 0,
            message: EchoReply{
                identifier: identifier,
                sequence: sequence,
                payload: payload,
            }
        })
    }
}

pub enum Icmpv6PacketBuildError {
    InvalidCode(u8),
}
use Icmpv6PacketBuildError::InvalidCode;

impl std::fmt::Display for Icmpv6PacketBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            InvalidCode(c) => format!("Invalid Code: {}", c),
        })
    }
}

impl From<Icmpv6PacketBuildError> for std::io::Error {
    fn from(err: Icmpv6PacketBuildError) -> Self {
        std::io::Error::new(std::io::ErrorKind::Other, format!("{}", err))
    }
}

#[cfg(test)]
mod checksum_tests {
    use super::*;

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
            0x20, 0x20, 0x75, 0x73, 0x74, 0x20, 0x61, 0x20,
            0x66, 0x6c, 0x65, 0x73, 0x68, 0x20, 0x77, 0x6f,
            0x75, 0x6e, 0x64, 0x20, 0x20, 0x74, 0x69, 0x73,
            0x20, 0x62, 0x75, 0x74, 0x20, 0x61, 0x20, 0x73,
            0x63, 0x72, 0x61, 0x74, 0x63, 0x68, 0x20, 0x20,
            0x6b, 0x6e, 0x69, 0x67, 0x68, 0x74, 0x73, 0x20,
            0x6f, 0x66, 0x20, 0x6e, 0x69, 0x20, 0x20, 0x20
        ];
        let mut pkt = Icmpv6Packet::parse(&data).unwrap();
        assert_eq!(pkt.typ, 128);
        assert_eq!(pkt.code, 0x00);
        if let EchoRequest{
            identifier,
            sequence,
            payload,
        }= &pkt.message {
            assert_eq!(*identifier, 0);
            assert_eq!(*sequence, 1);
            assert_eq!(payload, &[
                0x20, 0x20, 0x75, 0x73, 0x74, 0x20, 0x61, 0x20,
                0x66, 0x6c, 0x65, 0x73, 0x68, 0x20, 0x77, 0x6f,
                0x75, 0x6e, 0x64, 0x20, 0x20, 0x74, 0x69, 0x73,
                0x20, 0x62, 0x75, 0x74, 0x20, 0x61, 0x20, 0x73,
                0x63, 0x72, 0x61, 0x74, 0x63, 0x68, 0x20, 0x20,
                0x6b, 0x6e, 0x69, 0x67, 0x68, 0x74, 0x73, 0x20,
                0x6f, 0x66, 0x20, 0x6e, 0x69, 0x20, 0x20, 0x20
            ]);
        } else  {
            assert!(false, "Packet did not parse as an EchoRequest {:?}", pkt.message);
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
        if let EchoReply{
            identifier,
            sequence,
            payload,
        }= &pkt.message {
            assert_eq!(*identifier, 0);
            assert_eq!(*sequence, 1);
            assert_eq!(payload, &[
                0x20, 0x20, 0x75, 0x73, 0x74, 0x20, 0x61, 0x20,
                0x66, 0x6c, 0x65, 0x73, 0x68, 0x20, 0x77, 0x6f,
                0x75, 0x6e, 0x64, 0x20, 0x20, 0x74, 0x69, 0x73,
                0x20, 0x62, 0x75, 0x74, 0x20, 0x61, 0x20, 0x73,
                0x63, 0x72, 0x61, 0x74, 0x63, 0x68, 0x20, 0x20,
                0x6b, 0x6e, 0x69, 0x67, 0x68, 0x74, 0x73, 0x20,
                0x6f, 0x66, 0x20, 0x6e, 0x69, 0x20, 0x20, 0x20
            ]);
        } else  {
            assert!(false, "Packet did not parse as an EchoReply {:?}", pkt.message);
        }
        assert_eq!(pkt.get_bytes(true), data);
        assert_eq!(pkt.calculate_checksum(lo, lo), 0x1c2e);
    }
}