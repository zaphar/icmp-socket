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
pub mod addr;
mod checksum;
pub mod error;
mod filter;
pub mod icmpv4;
pub mod icmpv6;
pub mod machine;
pub mod options;
pub mod socket;
mod state;
mod sys;
mod wire;

pub use addr::ScopedIpv6Addr;
pub use error::{Ipv4RecvError, ModelledTypeError, ParseError, RecvError};
pub use filter::TypeFilter;
pub use icmpv4::{Icmpv4Message, Icmpv4Other};
pub use icmpv6::{Icmpv6Message, Icmpv6Other};
pub use socket::{
    DgramSocket4, DgramSocket6, DgramState4, DgramState6, RawSocket4, RawSocket6, RawState4,
    RawState6,
};
pub use state::{RecvInfo, SendOptions};

#[cfg(feature = "async")]
pub mod asynch;
#[cfg(feature = "async")]
pub use asynch::{AsyncDgramSocket4, AsyncDgramSocket6, AsyncRawSocket4, AsyncRawSocket6, Runtime};
#[cfg(feature = "async-io")]
#[path = "rt_async_io.rs"]
pub mod async_io;
#[cfg(feature = "tokio")]
#[path = "rt_tokio.rs"]
pub mod tokio;

// Compile the README examples as doctests so they stay correct.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
