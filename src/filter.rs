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
//! Filtering received messages by type.

/// A set of ICMP types for a socket's `set_type_filter`.
///
/// ```
/// use icmp_socket::TypeFilter;
/// use icmp_socket::icmpv4::msg_type;
///
/// let filter = TypeFilter::block_all()
///     .pass(msg_type::ECHO_REPLY)
///     .pass(msg_type::TIME_EXCEEDED);
/// assert!(filter.passes(msg_type::ECHO_REPLY));
/// assert!(!filter.passes(msg_type::ECHO_REQUEST));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TypeFilter {
    /// One bit per type; a set bit blocks the type.
    blocked: [u32; 8],
}

impl Default for TypeFilter {
    /// Pass every type.
    fn default() -> Self {
        Self::pass_all()
    }
}

impl TypeFilter {
    /// Pass every type.
    pub fn pass_all() -> Self {
        Self { blocked: [0; 8] }
    }

    /// Block every type.
    pub fn block_all() -> Self {
        Self {
            blocked: [u32::MAX; 8],
        }
    }

    /// Also pass `typ`.
    pub fn pass(mut self, typ: u8) -> Self {
        self.blocked[usize::from(typ >> 5)] &= !(1 << (typ & 31));
        self
    }

    /// Also block `typ`.
    pub fn block(mut self, typ: u8) -> Self {
        self.blocked[usize::from(typ >> 5)] |= 1 << (typ & 31);
        self
    }

    /// Whether messages of type `typ` pass.
    pub fn passes(&self, typ: u8) -> bool {
        self.blocked[usize::from(typ >> 5)] & (1 << (typ & 31)) == 0
    }

    /// The bitmap, one bit per type, a set bit blocking it.
    pub(crate) fn blocked(&self) -> [u32; 8] {
        self.blocked
    }

    /// Whether any type is blocked.
    pub(crate) fn blocks_any(&self) -> bool {
        self.blocked.iter().any(|w| *w != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pass_and_block_each_type() {
        for typ in 0..=255u8 {
            assert!(TypeFilter::pass_all().passes(typ));
            assert!(!TypeFilter::block_all().passes(typ));
            assert!(!TypeFilter::pass_all().block(typ).passes(typ));
            assert!(TypeFilter::block_all().pass(typ).passes(typ));
            let one = TypeFilter::block_all().pass(typ);
            assert!((0..=255u8).filter(|t| one.passes(*t)).eq([typ]));
        }
    }
}
