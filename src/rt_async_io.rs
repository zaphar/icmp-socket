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
//! The async-io runtime (feature `async-io`).
//!
//! ```no_run
//! # fn example() -> std::io::Result<()> {
//! async_io::block_on(async {
//!     let mut socket = icmp_socket::async_io::DgramSocket4::open()?;
//!     socket.send_echo(std::net::Ipv4Addr::LOCALHOST, 1, b"ping").await?;
//!     let (reply, from) = socket.recv_from().await?;
//!     Ok(())
//! })
//! # }
//! ```
use std::future::Future;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use ::async_io::Async;

use crate::asynch::{self, Runtime};
use crate::machine::Interest;

/// The async-io runtime.
pub enum AsyncIo {}

impl Runtime for AsyncIo {
    type Registered = Async<OwnedFd>;

    fn register(fd: OwnedFd) -> io::Result<Async<OwnedFd>> {
        Async::new(fd)
    }

    fn io<T: Send>(
        fd: &Async<OwnedFd>,
        interest: Interest,
        mut op: impl FnMut(BorrowedFd<'_>) -> io::Result<T> + Send,
    ) -> impl Future<Output = io::Result<T>> + Send {
        // async-io counts an error condition as readable.
        async move {
            match interest {
                Interest::Write => fd.write_with(|fd| op(fd.as_fd())).await,
                Interest::Read | Interest::None => fd.read_with(|fd| op(fd.as_fd())).await,
            }
        }
    }
}

/// An async raw ICMPv4 socket on async-io.
pub type RawSocket4 = asynch::AsyncRawSocket4<AsyncIo>;
/// An async raw ICMPv6 socket on async-io.
pub type RawSocket6 = asynch::AsyncRawSocket6<AsyncIo>;
/// An async datagram ICMPv4 socket on async-io.
pub type DgramSocket4 = asynch::AsyncDgramSocket4<AsyncIo>;
/// An async datagram ICMPv6 socket on async-io.
pub type DgramSocket6 = asynch::AsyncDgramSocket6<AsyncIo>;
