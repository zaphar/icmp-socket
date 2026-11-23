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
//! Option lists.
//!
//! Several message types end with a list of options. The message variants
//! keep the list as raw bytes. [`Options`] reads such a list and
//! [`OptionsBuilder`] writes one; an [`OptionFormat`] describes how one
//! option is laid out. The crate provides the formats ICMP uses:
//!
//! - [`NdOptionFormat`]: Neighbor Discovery options (RFC 4861 section 4.6).
//! - [`ExtensionObjectFormat`]: RFC 4884 extension objects.
//! - [`RplOptionFormat`]: RPL control message options (RFC 6550 section 6.7).
//!
//! Receivers skip option types they do not know (RFC 4861), so option types
//! are plain numbers with named constants, not an enum:
//!
//! ```
//! use icmp_socket::options::{NdOptionFormat, Options, nd_option};
//!
//! # let bytes = [5, 1, 0, 0, 0, 0, 0x05, 0xdc];
//! for opt in Options::<NdOptionFormat>::new(&bytes) {
//!     let opt = opt?;
//!     if opt.kind == nd_option::MTU {
//!         // ...
//!     }
//! }
//! # Ok::<(), icmp_socket::options::OptionError>(())
//! ```
use std::fmt;
use std::marker::PhantomData;
use std::net::Ipv6Addr;

/// One option read from a list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawOption<'a, K> {
    /// The option type.
    pub kind: K,
    /// The option's data: every byte after its type and length fields,
    /// including any padding.
    pub data: &'a [u8],
}

/// Why an option could not be read or written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionError {
    /// The list ends inside an option.
    Truncated { needed: usize, actual: usize },
    /// The option's length field holds a value the format forbids (e.g. 0
    /// for a Neighbor Discovery option).
    BadLength { length: usize },
    /// The data is too long for the format's length field.
    TooLong { length: usize, max: usize },
}

impl fmt::Display for OptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OptionError::Truncated { needed, actual } => write!(
                f,
                "option list ends inside an option: {} bytes left, the option needs {}",
                actual, needed
            ),
            OptionError::BadLength { length } => {
                write!(f, "option length {} is not valid for this format", length)
            }
            OptionError::TooLong { length, max } => write!(
                f,
                "option data of {} bytes is longer than the format allows ({})",
                length, max
            ),
        }
    }
}

impl std::error::Error for OptionError {}

/// The layout of one option in a list. Implement it to read and write a
/// format this crate does not provide.
pub trait OptionFormat {
    /// The option type: a number, or e.g. a class and sub-type pair.
    type Kind: Copy;

    /// Read one option from the start of `bytes`. Return it and the bytes
    /// after it.
    fn decode(bytes: &[u8]) -> Result<(RawOption<'_, Self::Kind>, &[u8]), OptionError>;

    /// Append one option (its header, `data` and any padding) to `out`.
    fn encode(kind: Self::Kind, data: &[u8], out: &mut Vec<u8>) -> Result<(), OptionError>;
}

/// Reads an option list. Yields each option, or one error and then stops.
pub struct Options<'a, F: OptionFormat> {
    rest: &'a [u8],
    failed: bool,
    format: PhantomData<F>,
}

impl<'a, F: OptionFormat> Options<'a, F> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            rest: bytes,
            failed: false,
            format: PhantomData,
        }
    }
}

impl<'a, F: OptionFormat> Iterator for Options<'a, F> {
    type Item = Result<RawOption<'a, F::Kind>, OptionError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.rest.is_empty() {
            return None;
        }
        match F::decode(self.rest) {
            Ok((opt, rest)) => {
                self.rest = rest;
                Some(Ok(opt))
            }
            Err(e) => {
                self.failed = true;
                Some(Err(e))
            }
        }
    }
}

impl<F: OptionFormat> std::iter::FusedIterator for Options<'_, F> {}

/// Writes an option list.
pub struct OptionsBuilder<F: OptionFormat> {
    out: Vec<u8>,
    format: PhantomData<F>,
}

impl<F: OptionFormat> Default for OptionsBuilder<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: OptionFormat> OptionsBuilder<F> {
    pub fn new() -> Self {
        Self {
            out: Vec::new(),
            format: PhantomData,
        }
    }

    /// Append one option.
    pub fn option(mut self, kind: F::Kind, data: &[u8]) -> Result<Self, OptionError> {
        F::encode(kind, data, &mut self.out)?;
        Ok(self)
    }

    /// The finished list.
    pub fn build(self) -> Vec<u8> {
        self.out
    }
}

fn need(bytes: &[u8], len: usize) -> Result<(), OptionError> {
    if bytes.len() < len {
        return Err(OptionError::Truncated {
            needed: len,
            actual: bytes.len(),
        });
    }
    Ok(())
}

/// Neighbor Discovery options (RFC 4861 section 4.6): a type byte, a length
/// byte counting the whole option in units of 8 bytes, then data. Length 0
/// is invalid. Used by Neighbor Discovery, SEND and Mobile IPv6 messages.
pub struct NdOptionFormat;

impl OptionFormat for NdOptionFormat {
    type Kind = u8;

    fn decode(bytes: &[u8]) -> Result<(RawOption<'_, u8>, &[u8]), OptionError> {
        need(bytes, 2)?;
        let units = usize::from(bytes[1]);
        if units == 0 {
            return Err(OptionError::BadLength { length: 0 });
        }
        let len = units * 8;
        need(bytes, len)?;
        Ok((
            RawOption {
                kind: bytes[0],
                data: &bytes[2..len],
            },
            &bytes[len..],
        ))
    }

    /// Pads the option with zeros to a multiple of 8 bytes.
    fn encode(kind: u8, data: &[u8], out: &mut Vec<u8>) -> Result<(), OptionError> {
        let len = (2 + data.len()).div_ceil(8) * 8;
        if len > 255 * 8 {
            return Err(OptionError::TooLong {
                length: data.len(),
                max: 255 * 8 - 2,
            });
        }
        out.push(kind);
        out.push((len / 8) as u8);
        out.extend_from_slice(data);
        out.resize(out.len() + len - 2 - data.len(), 0);
        Ok(())
    }
}

/// The type of an RFC 4884 extension object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectKind {
    /// The class number (C-Num).
    pub class: u8,
    /// The sub-type within the class (C-Type).
    pub sub_type: u8,
}

/// RFC 4884 extension objects: a 2-byte length counting the whole object in
/// bytes (at least 4), a class number, a sub-type, then data. The objects
/// follow the 4-byte extension header; see [`ExtensionHeader`].
pub struct ExtensionObjectFormat;

impl OptionFormat for ExtensionObjectFormat {
    type Kind = ObjectKind;

    fn decode(bytes: &[u8]) -> Result<(RawOption<'_, ObjectKind>, &[u8]), OptionError> {
        need(bytes, 4)?;
        let len = usize::from(u16::from_be_bytes([bytes[0], bytes[1]]));
        if len < 4 {
            return Err(OptionError::BadLength { length: len });
        }
        need(bytes, len)?;
        Ok((
            RawOption {
                kind: ObjectKind {
                    class: bytes[2],
                    sub_type: bytes[3],
                },
                data: &bytes[4..len],
            },
            &bytes[len..],
        ))
    }

    fn encode(kind: ObjectKind, data: &[u8], out: &mut Vec<u8>) -> Result<(), OptionError> {
        let len = 4 + data.len();
        let len = u16::try_from(len).map_err(|_| OptionError::TooLong {
            length: data.len(),
            max: usize::from(u16::MAX) - 4,
        })?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&[kind.class, kind.sub_type]);
        out.extend_from_slice(data);
        Ok(())
    }
}

/// The 4-byte header of an RFC 4884 extension structure, which precedes the
/// extension objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtensionHeader {
    /// The version (the high 4 bits); RFC 4884 defines version 2.
    pub version: u8,
    /// The 12 reserved bits.
    pub reserved: u16,
    /// The checksum of the extension structure.
    pub checksum: u16,
}

impl ExtensionHeader {
    /// Split an extension structure into its header and its objects, which
    /// [`Options<ExtensionObjectFormat>`] reads.
    pub fn split(bytes: &[u8]) -> Result<(Self, &[u8]), OptionError> {
        need(bytes, 4)?;
        let first = u16::from_be_bytes([bytes[0], bytes[1]]);
        Ok((
            Self {
                version: (first >> 12) as u8,
                reserved: first & 0x0FFF,
                checksum: u16::from_be_bytes([bytes[2], bytes[3]]),
            },
            &bytes[4..],
        ))
    }
}

/// RPL control message options (RFC 6550 section 6.7.1): a type byte, a
/// length byte counting the data in bytes, then data. Type 0 (Pad1) is a
/// single byte with no length or data.
pub struct RplOptionFormat;

impl OptionFormat for RplOptionFormat {
    type Kind = u8;

    fn decode(bytes: &[u8]) -> Result<(RawOption<'_, u8>, &[u8]), OptionError> {
        need(bytes, 1)?;
        if bytes[0] == rpl_option::PAD1 {
            return Ok((
                RawOption {
                    kind: rpl_option::PAD1,
                    data: &[],
                },
                &bytes[1..],
            ));
        }
        need(bytes, 2)?;
        let len = 2 + usize::from(bytes[1]);
        need(bytes, len)?;
        Ok((
            RawOption {
                kind: bytes[0],
                data: &bytes[2..len],
            },
            &bytes[len..],
        ))
    }

    fn encode(kind: u8, data: &[u8], out: &mut Vec<u8>) -> Result<(), OptionError> {
        if kind == rpl_option::PAD1 {
            if !data.is_empty() {
                return Err(OptionError::TooLong {
                    length: data.len(),
                    max: 0,
                });
            }
            out.push(rpl_option::PAD1);
            return Ok(());
        }
        let len = u8::try_from(data.len()).map_err(|_| OptionError::TooLong {
            length: data.len(),
            max: 255,
        })?;
        out.push(kind);
        out.push(len);
        out.extend_from_slice(data);
        Ok(())
    }
}

/// Neighbor Discovery option types (IANA "IPv6 Neighbor Discovery Option
/// Formats").
pub mod nd_option {
    pub const SOURCE_LINK_LAYER_ADDRESS: u8 = 1;
    pub const TARGET_LINK_LAYER_ADDRESS: u8 = 2;
    pub const PREFIX_INFORMATION: u8 = 3;
    pub const REDIRECTED_HEADER: u8 = 4;
    pub const MTU: u8 = 5;
    pub const NBMA_SHORTCUT_LIMIT: u8 = 6;
    pub const ADVERTISEMENT_INTERVAL: u8 = 7;
    pub const HOME_AGENT_INFORMATION: u8 = 8;
    pub const SOURCE_ADDRESS_LIST: u8 = 9;
    pub const TARGET_ADDRESS_LIST: u8 = 10;
    pub const CGA: u8 = 11;
    pub const RSA_SIGNATURE: u8 = 12;
    pub const TIMESTAMP: u8 = 13;
    pub const NONCE: u8 = 14;
    pub const TRUST_ANCHOR: u8 = 15;
    pub const CERTIFICATE: u8 = 16;
    pub const IP_ADDRESS_PREFIX: u8 = 17;
    pub const NEW_ROUTER_PREFIX_INFORMATION: u8 = 18;
    pub const LINK_LAYER_ADDRESS: u8 = 19;
    pub const NEIGHBOR_ADVERTISEMENT_ACKNOWLEDGMENT: u8 = 20;
    pub const PVD_ID_ROUTER_ADVERTISEMENT: u8 = 21;
    pub const MAP: u8 = 23;
    pub const ROUTE_INFORMATION: u8 = 24;
    pub const RECURSIVE_DNS_SERVER: u8 = 25;
    pub const RA_FLAGS_EXTENSION: u8 = 26;
    pub const HANDOVER_KEY_REQUEST: u8 = 27;
    pub const HANDOVER_KEY_REPLY: u8 = 28;
    pub const HANDOVER_ASSIST_INFORMATION: u8 = 29;
    pub const MOBILE_NODE_IDENTIFIER: u8 = 30;
    pub const DNS_SEARCH_LIST: u8 = 31;
    pub const PROXY_SIGNATURE: u8 = 32;
    pub const ADDRESS_REGISTRATION: u8 = 33;
    pub const SIXLOWPAN_CONTEXT: u8 = 34;
    pub const AUTHORITATIVE_BORDER_ROUTER: u8 = 35;
    pub const SIXLOWPAN_CAPABILITY_INDICATION: u8 = 36;
    pub const DHCP_CAPTIVE_PORTAL: u8 = 37;
    pub const PREF64: u8 = 38;
    pub const CRYPTO_ID_PARAMETERS: u8 = 39;
    pub const NDP_SIGNATURE: u8 = 40;
    pub const RESOURCE_DIRECTORY_ADDRESS: u8 = 41;
    pub const CONSISTENT_UPTIME: u8 = 42;
    pub const CARD_REQUEST: u8 = 138;
    pub const CARD_REPLY: u8 = 139;
    pub const ENCRYPTED_DNS: u8 = 144;
    pub const EXPERIMENT_1: u8 = 253;
    pub const EXPERIMENT_2: u8 = 254;
}

/// RPL control message option types (IANA "RPL Control Message Options").
pub mod rpl_option {
    /// One byte of padding, with no length or data.
    pub const PAD1: u8 = 0x00;
    pub const PADN: u8 = 0x01;
    pub const DAG_METRIC_CONTAINER: u8 = 0x02;
    pub const ROUTING_INFORMATION: u8 = 0x03;
    pub const DODAG_CONFIGURATION: u8 = 0x04;
    pub const RPL_TARGET: u8 = 0x05;
    pub const TRANSIT_INFORMATION: u8 = 0x06;
    pub const SOLICITED_INFORMATION: u8 = 0x07;
    pub const PREFIX_INFORMATION: u8 = 0x08;
    pub const TARGET_DESCRIPTOR: u8 = 0x09;
    pub const P2P_ROUTE_DISCOVERY: u8 = 0x0A;
    pub const RREQ: u8 = 0x0B;
    pub const RREP: u8 = 0x0C;
    pub const ART: u8 = 0x0D;
    pub const RNFD: u8 = 0x0E;
    pub const STATEFUL_STORING_MODE_VIO: u8 = 0x0F;
    pub const SOURCE_ROUTED_NON_STORING_MODE_VIO: u8 = 0x10;
    pub const SIBLING_INFORMATION: u8 = 0x11;
}

/// RFC 4884 extension object classes (IANA "ICMP Extension Object Classes
/// and Class Sub-types").
pub mod extension_class {
    pub const MPLS_LABEL_STACK: u8 = 1;
    pub const INTERFACE_INFORMATION: u8 = 2;
    pub const INTERFACE_IDENTIFICATION: u8 = 3;
    pub const EXTENDED_INFORMATION: u8 = 4;
}

/// The Neighbor Discovery Prefix Information option (type 3, RFC 4861
/// section 4.6.2): the 30 data bytes after the type and length fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrefixInformation {
    pub prefix_length: u8,
    /// The flag bits; see [`prefix_flags`].
    pub flags: u8,
    pub valid_lifetime: u32,
    pub preferred_lifetime: u32,
    pub reserved: u32,
    pub prefix: Ipv6Addr,
}

/// Prefix Information flag bits.
pub mod prefix_flags {
    /// On-link (RFC 4861).
    pub const ON_LINK: u8 = 0x80;
    /// Autonomous address configuration (RFC 4861).
    pub const AUTONOMOUS: u8 = 0x40;
    /// Router address (RFC 6275).
    pub const ROUTER_ADDRESS: u8 = 0x20;
    /// DHCPv6 prefix delegation preferred (RFC 9762).
    pub const DHCPV6_PD_PREFERRED: u8 = 0x10;
}

impl PrefixInformation {
    /// The data length, without the type and length fields.
    pub const LEN: usize = 30;

    /// Parse the option's data (see [`RawOption::data`]).
    pub fn parse(data: &[u8]) -> Result<Self, OptionError> {
        need(data, Self::LEN)?;
        let u32_at =
            |i: usize| u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let mut prefix = [0; 16];
        prefix.copy_from_slice(&data[14..30]);
        Ok(Self {
            prefix_length: data[0],
            flags: data[1],
            valid_lifetime: u32_at(2),
            preferred_lifetime: u32_at(6),
            reserved: u32_at(10),
            prefix: Ipv6Addr::from(prefix),
        })
    }

    /// The option's data, for [`OptionsBuilder::option`].
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LEN);
        out.push(self.prefix_length);
        out.push(self.flags);
        out.extend_from_slice(&self.valid_lifetime.to_be_bytes());
        out.extend_from_slice(&self.preferred_lifetime.to_be_bytes());
        out.extend_from_slice(&self.reserved.to_be_bytes());
        out.extend_from_slice(&self.prefix.octets());
        out
    }
}

/// The Neighbor Discovery MTU option (type 5, RFC 4861 section 4.6.4): the
/// 6 data bytes after the type and length fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MtuOption {
    pub reserved: u16,
    pub mtu: u32,
}

impl MtuOption {
    /// The data length, without the type and length fields.
    pub const LEN: usize = 6;

    /// Parse the option's data (see [`RawOption::data`]).
    pub fn parse(data: &[u8]) -> Result<Self, OptionError> {
        need(data, Self::LEN)?;
        Ok(Self {
            reserved: u16::from_be_bytes([data[0], data[1]]),
            mtu: u32::from_be_bytes([data[2], data[3], data[4], data[5]]),
        })
    }

    /// The option's data, for [`OptionsBuilder::option`].
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LEN);
        out.extend_from_slice(&self.reserved.to_be_bytes());
        out.extend_from_slice(&self.mtu.to_be_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nd_options_round_trip_with_padding() {
        let mtu = MtuOption {
            reserved: 0,
            mtu: 1500,
        };
        let list = OptionsBuilder::<NdOptionFormat>::new()
            .option(nd_option::MTU, &mtu.to_bytes())
            .unwrap()
            .option(nd_option::SOURCE_LINK_LAYER_ADDRESS, &[1, 2, 3, 4, 5, 6])
            .unwrap()
            .build();
        assert_eq!(list.len(), 16);
        let opts: Vec<_> = Options::<NdOptionFormat>::new(&list)
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(opts.len(), 2);
        assert_eq!(opts[0].kind, nd_option::MTU);
        assert_eq!(MtuOption::parse(opts[0].data).unwrap(), mtu);
        assert_eq!(&opts[1].data[..6], &[1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn nd_zero_length_and_truncation_are_errors() {
        let mut it = Options::<NdOptionFormat>::new(&[1, 0, 0, 0]);
        assert_eq!(it.next(), Some(Err(OptionError::BadLength { length: 0 })));
        assert_eq!(it.next(), None);
        assert_eq!(
            Options::<NdOptionFormat>::new(&[1, 2, 0, 0]).next(),
            Some(Err(OptionError::Truncated {
                needed: 16,
                actual: 4
            }))
        );
    }

    #[test]
    fn extension_objects_round_trip() {
        let kind = ObjectKind {
            class: 1,
            sub_type: 1,
        };
        let list = OptionsBuilder::<ExtensionObjectFormat>::new()
            .option(kind, &[0, 0, 0, 7])
            .unwrap()
            .build();
        let opt = Options::<ExtensionObjectFormat>::new(&list)
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(opt.kind, kind);
        assert_eq!(opt.data, &[0, 0, 0, 7]);
        let (header, objects) = ExtensionHeader::split(&[0x20, 0, 0x12, 0x34, 9]).unwrap();
        assert_eq!(header.version, 2);
        assert_eq!(header.checksum, 0x1234);
        assert_eq!(objects, &[9]);
    }

    #[test]
    fn rpl_pad1_is_one_byte() {
        let list = OptionsBuilder::<RplOptionFormat>::new()
            .option(rpl_option::PAD1, &[])
            .unwrap()
            .option(4, &[1, 2])
            .unwrap()
            .build();
        assert_eq!(list, vec![0, 4, 2, 1, 2]);
        let opts: Vec<_> = Options::<RplOptionFormat>::new(&list)
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(opts[0].kind, rpl_option::PAD1);
        assert_eq!(opts[1].data, &[1, 2]);
    }

    #[test]
    fn prefix_information_round_trips() {
        let p = PrefixInformation {
            prefix_length: 64,
            flags: prefix_flags::ON_LINK | prefix_flags::AUTONOMOUS,
            valid_lifetime: 86400,
            preferred_lifetime: 14400,
            reserved: 0,
            prefix: "2001:db8::".parse().unwrap(),
        };
        assert_eq!(PrefixInformation::parse(&p.to_bytes()).unwrap(), p);
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// The longest input the proofs cover. A decoder reads at most the first four
    /// bytes; the rest of the input matters only through its length.
    const MAX: usize = 2048;

    /// One call to `next` on any list state never panics, and either stops
    /// without a change, or reads at least one byte, or fails. So a list of
    /// `n` bytes yields at most `n + 1` items, then `None` for ever.
    fn next_step<F: OptionFormat>() {
        let buf: [u8; MAX] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= MAX);
        let mut list = Options::<F> {
            rest: &buf[..len],
            failed: kani::any(),
            format: PhantomData,
        };
        let failed = list.failed;
        match list.next() {
            None => {
                assert!((failed || len == 0) && list.failed == failed && list.rest.len() == len)
            }
            Some(Ok(_)) => assert!(!list.failed && list.rest.len() < len),
            Some(Err(_)) => assert!(!failed && list.failed),
        }
    }

    #[kani::proof]
    fn nd_options_step() {
        next_step::<NdOptionFormat>();
    }

    #[kani::proof]
    fn extension_objects_step() {
        next_step::<ExtensionObjectFormat>();
    }

    #[kani::proof]
    fn rpl_options_step() {
        next_step::<RplOptionFormat>();
    }
}
