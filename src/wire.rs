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
//! Reading and writing the fixed fields of a message.
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::ParseError;

/// Reads big-endian fields from the bytes of one ICMP message. Every read is
/// bounds-checked against the whole message, so a short message is a
/// `TooShort` error and never a panic.
pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// A reader positioned after the 4-byte common header.
    pub(crate) fn after_header(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 4 }
    }

    /// Fail unless the message has at least `len` bytes.
    pub(crate) fn need(&self, len: usize) -> Result<(), ParseError> {
        if self.bytes.len() < len {
            return Err(ParseError::TooShort {
                needed: len,
                actual: self.bytes.len(),
            });
        }
        Ok(())
    }

    /// Fail unless the message has exactly `len` bytes.
    pub(crate) fn exactly(&self, len: usize) -> Result<(), ParseError> {
        self.need(len)?;
        if self.bytes.len() > len {
            return Err(ParseError::TrailingBytes {
                expected: len,
                actual: self.bytes.len(),
            });
        }
        Ok(())
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], ParseError> {
        self.need(self.pos + N)?;
        let mut out = [0; N];
        out.copy_from_slice(&self.bytes[self.pos..self.pos + N]);
        self.pos += N;
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, ParseError> {
        Ok(self.array::<1>()?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16, ParseError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, ParseError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub(crate) fn ipv4(&mut self) -> Result<Ipv4Addr, ParseError> {
        Ok(Ipv4Addr::from(self.array::<4>()?))
    }

    pub(crate) fn ipv6(&mut self) -> Result<Ipv6Addr, ParseError> {
        Ok(Ipv6Addr::from(self.array::<16>()?))
    }

    /// The bytes from the current position up to `len` bytes before the
    /// end of the message.
    pub(crate) fn until_last(&mut self, len: usize) -> Vec<u8> {
        let end = self.bytes.len().saturating_sub(len).max(self.pos);
        let out = self.bytes[self.pos..end].to_vec();
        self.pos = end;
        out
    }

    /// Every byte after the current position.
    pub(crate) fn rest(&mut self) -> Vec<u8> {
        let rest = self.bytes.get(self.pos..).unwrap_or(&[]).to_vec();
        self.pos = self.bytes.len();
        rest
    }
}

/// Appends big-endian fields to a message being serialized.
pub(crate) struct Writer<'a> {
    out: &'a mut Vec<u8>,
}

impl<'a> Writer<'a> {
    /// Start a message: type, code and a zero checksum field.
    pub(crate) fn header(out: &'a mut Vec<u8>, typ: u8, code: u8) -> Self {
        out.extend_from_slice(&[typ, code, 0, 0]);
        Self { out }
    }

    pub(crate) fn bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.out.extend_from_slice(bytes);
        self
    }

    pub(crate) fn u8(&mut self, v: u8) -> &mut Self {
        self.bytes(&[v])
    }

    pub(crate) fn u16(&mut self, v: u16) -> &mut Self {
        self.bytes(&v.to_be_bytes())
    }

    pub(crate) fn u32(&mut self, v: u32) -> &mut Self {
        self.bytes(&v.to_be_bytes())
    }

    pub(crate) fn ipv4(&mut self, a: &Ipv4Addr) -> &mut Self {
        self.bytes(&a.octets())
    }

    pub(crate) fn ipv6(&mut self, a: &Ipv6Addr) -> &mut Self {
        self.bytes(&a.octets())
    }
}

/// Fail unless `bytes` holds at least the 4-byte common header.
pub(crate) fn check_header(bytes: &[u8]) -> Result<(), ParseError> {
    if bytes.len() < 4 {
        return Err(ParseError::TooShort {
            needed: 4,
            actual: bytes.len(),
        });
    }
    Ok(())
}
