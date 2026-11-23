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
//! The tokio runtime (feature `tokio`).
//!
//! ```no_run
//! # async fn example() -> std::io::Result<()> {
//! let mut socket = icmp_socket::tokio::DgramSocket4::open()?;
//! socket.send_echo(std::net::Ipv4Addr::LOCALHOST, 1, b"ping").await?;
//! let (reply, from) = socket.recv_from().await?;
//! # Ok(())
//! # }
//! ```
use std::future::Future;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use ::tokio::io::unix::AsyncFd;

use crate::asynch::{self, Runtime};
use crate::machine::Interest;

/// The tokio runtime. Sockets must be created inside a tokio runtime.
pub enum Tokio {}

impl Runtime for Tokio {
    type Registered = AsyncFd<OwnedFd>;

    /// Panics outside a tokio runtime, as tokio's registration does.
    fn register(fd: OwnedFd) -> io::Result<AsyncFd<OwnedFd>> {
        // SAFETY: an OwnedFd holds one open descriptor for its whole
        // lifetime and always returns it from as_raw_fd.
        Ok(unsafe { AsyncFd::register(fd) }?)
    }

    fn io<T: Send>(
        fd: &AsyncFd<OwnedFd>,
        interest: Interest,
        mut op: impl FnMut(BorrowedFd<'_>) -> io::Result<T> + Send,
    ) -> impl Future<Output = io::Result<T>> + Send {
        // tokio's READABLE does not include error readiness, which a queued
        // ICMP error on a Linux datagram socket signals.
        let interest = match interest {
            Interest::Write => ::tokio::io::Interest::WRITABLE,
            Interest::Read | Interest::None => {
                ::tokio::io::Interest::READABLE | ::tokio::io::Interest::ERROR
            }
        };
        fd.async_io(interest, move |fd| op(fd.as_fd()))
    }
}

/// An async raw ICMPv4 socket on tokio.
pub type RawSocket4 = asynch::AsyncRawSocket4<Tokio>;
/// An async raw ICMPv6 socket on tokio.
pub type RawSocket6 = asynch::AsyncRawSocket6<Tokio>;
/// An async datagram ICMPv4 socket on tokio.
pub type DgramSocket4 = asynch::AsyncDgramSocket4<Tokio>;
/// An async datagram ICMPv6 socket on tokio.
pub type DgramSocket6 = asynch::AsyncDgramSocket6<Tokio>;
