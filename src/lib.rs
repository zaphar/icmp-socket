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
//! An ICMP socket library that tries to be ergonomic to use.
//!
//! The standard ping examples for both Ipv6 and IPv4 are in the examples
//! directory.
mod checksum;
pub mod error;
pub mod icmpv4;
pub mod icmpv6;
pub mod socket;
mod wire;

pub use error::{ModelledTypeError, ParseError};
pub use icmpv4::{Icmpv4Message, Icmpv4Other};
pub use icmpv6::{Icmpv6Message, Icmpv6Other};
pub use socket::{DgramIcmpSocket4, IcmpSocket, IcmpSocket4, IcmpSocket6};
#[cfg(feature = "smol")]
pub mod smol;

// Compile the README examples as doctests so they stay correct.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
