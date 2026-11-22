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
//! The Internet checksum (RFC 1071) as ICMPv4 and ICMPv6 use it.
use std::net::Ipv6Addr;

/// The one's complement sum of `bytes` as big-endian 16-bit words, before
/// folding. An odd last byte is the high byte of a final word. The sum is a
/// u64 so that no slice a caller can pass overflows it.
pub(crate) fn sum_words(bytes: &[u8]) -> u64 {
    let mut chunks = bytes.chunks_exact(2);
    let mut sum: u64 = chunks
        .by_ref()
        .map(|w| u64::from(u16::from_be_bytes([w[0], w[1]])))
        .sum();
    if let [last] = chunks.remainder() {
        sum += u64::from(*last) << 8;
    }
    sum
}

/// Fold the carries of a one's complement sum into 16 bits.
pub(crate) fn fold(mut sum: u64) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }
    sum as u16
}

/// The ICMPv6 pseudo-header sum (RFC 4443 section 2.3) for a message of
/// `len` bytes.
pub(crate) fn ipv6_pseudo_header(src: &Ipv6Addr, dst: &Ipv6Addr, len: usize) -> u64 {
    // 58 is the IPv6 next header value for ICMPv6.
    sum_words(&src.octets()) + sum_words(&dst.octets()) + len as u64 + 58
}

/// Write the checksum of `message` (whose checksum field is zero) into
/// bytes 2 and 3. `extra` is any pseudo-header sum.
pub(crate) fn fill(message: &mut [u8], extra: u64) {
    let checksum = !fold(sum_words(message) + extra);
    message[2..4].copy_from_slice(&checksum.to_be_bytes());
}

/// Whether `message`, checksum field included, sums to 0xFFFF.
pub(crate) fn verifies(message: &[u8], extra: u64) -> bool {
    message.len() >= 4 && fold(sum_words(message) + extra) == 0xFFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_echo_request_checksum() {
        // Type 8, code 0, identifier 1, sequence 1, no payload.
        let mut msg = [8, 0, 0, 0, 0, 1, 0, 1];
        fill(&mut msg, 0);
        assert_eq!(u16::from_be_bytes([msg[2], msg[3]]), 0xf7fd);
        assert!(verifies(&msg, 0));
    }

    #[test]
    fn odd_length_pads_the_last_byte() {
        assert_eq!(sum_words(&[0x12, 0x34, 0x56]), 0x1234 + 0x5600);
    }
}
