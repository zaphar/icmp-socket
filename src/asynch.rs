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
//! Async ICMP sockets for any runtime (feature `async`).
//!
//! The async sockets are generic over a [`Runtime`]. The crate provides
//! [`crate::tokio::Tokio`] (feature `tokio`) and [`crate::async_io::AsyncIo`]
//! (feature `async-io`); each module has short aliases such as
//! `icmp_socket::tokio::DgramSocket4`. Implement [`Runtime`] for any other
//! runtime: it forwards to the runtime's own "run this non-blocking call when
//! the descriptor is ready" helper.
//!
//! Async receives have no timeout; use the runtime's (e.g.
//! `tokio::time::timeout`).
use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};

use socket2::SockRef;

use crate::addr::ScopedIpv6Addr;
use crate::error::{Ipv4RecvError, RecvError};
use crate::filter::TypeFilter;
use crate::machine::{Machine, Next, Operation, Progress};
use crate::state::{RecvInfo, SendOptions};
use crate::{
    DgramSocket4, DgramSocket6, DgramState4, DgramState6, Icmpv4Message, Icmpv6Message, RawSocket4,
    RawSocket6, RawState4, RawState6,
};

/// An async runtime the async sockets can wait with.
pub trait Runtime {
    /// The descriptor, registered with the runtime's reactor.
    type Registered: AsFd + Send + Sync;

    /// Register a non-blocking descriptor with the runtime.
    fn register(fd: OwnedFd) -> io::Result<Self::Registered>;

    /// Run `op` when `fd` is ready for `operation`; when `op` fails with
    /// `WouldBlock`, wait and run it again. `Operation::Read` must also wake
    /// for an error condition on the descriptor.
    fn io<T: Send>(
        fd: &Self::Registered,
        operation: Operation,
        op: impl FnMut(BorrowedFd<'_>) -> io::Result<T> + Send,
    ) -> impl Future<Output = io::Result<T>> + Send;
}

/// Run a machine to completion with a runtime.
async fn drive<R: Runtime, M: Machine + Send>(fd: &R::Registered, mut machine: M) -> M::Output {
    loop {
        match machine.next() {
            Next::Done(out) => return out,
            Next::Io(operation) => {
                let ready = R::io(fd, operation, |fd| match machine.perform(fd) {
                    Progress::Continue => Ok(()),
                    Progress::WouldBlock => Err(io::ErrorKind::WouldBlock.into()),
                })
                .await;
                if let Err(e) = ready {
                    machine.fail(e);
                }
            }
        }
    }
}

fn local_v4(fd: BorrowedFd<'_>) -> io::Result<Ipv4Addr> {
    match SockRef::from(&fd).local_addr()?.as_socket() {
        Some(std::net::SocketAddr::V4(a)) => Ok(*a.ip()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "socket has no IPv4 address",
        )),
    }
}

fn local_v6(fd: BorrowedFd<'_>) -> io::Result<ScopedIpv6Addr> {
    match SockRef::from(&fd).local_addr()?.as_socket() {
        Some(std::net::SocketAddr::V6(a)) => Ok(a.into()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "socket has no IPv6 address",
        )),
    }
}

/// The methods every async socket kind has.
macro_rules! async_common {
    (
        $async:ident, $blocking:ident, $state:ident,
        addr = $addr:ty, msg = $msg:ty, proto = $proto:ty, local = $local:path
    ) => {
        impl<R: Runtime> $async<R> {
            /// Open an unbound socket.
            pub fn open() -> io::Result<Self> {
                $blocking::open()?.into_async()
            }

            /// Open a socket bound to a local address.
            pub fn bind(addr: impl Into<$addr>) -> io::Result<Self> {
                $blocking::bind(addr)?.into_async()
            }

            /// The local address, as the kernel reports it.
            pub fn local_addr(&self) -> io::Result<$addr> {
                $local(self.fd.as_fd())
            }

            /// The largest message a receive accepts (default 2048 bytes).
            pub fn set_max_message_size(&mut self, size: usize) {
                self.state.set_max_message_size(size);
            }

            /// Receive only messages whose type passes `filter`. The same
            /// filter gives the same result on every socket: the kernel filters
            /// where it can (`ICMP6_FILTER` on raw ICMPv6 sockets, `ICMP_FILTER`
            /// for ICMPv4 types 0 to 31 on Linux raw sockets), and the socket
            /// drops the other blocked messages itself and keeps waiting.
            pub fn set_type_filter(&mut self, filter: &TypeFilter) -> io::Result<()> {
                self.state.set_type_filter(self.fd.as_fd(), filter)
            }

            /// Receive a message and the address it came from.
            pub async fn recv_from(&mut self) -> Result<($msg, $addr), RecvError<$proto>> {
                drive::<R, _>(&self.fd, self.state.recv_from()).await
            }

            /// Receive a message and facts about its packet.
            pub async fn recv_with_info(
                &mut self,
            ) -> Result<($msg, RecvInfo<$addr>), RecvError<$proto>> {
                drive::<R, _>(&self.fd, self.state.recv_with_info()).await
            }

            /// Receive a message as ICMP bytes, unparsed and unchecked.
            pub async fn recv_raw(
                &mut self,
            ) -> Result<(&[u8], RecvInfo<$addr>), RecvError<$proto>> {
                drive::<R, _>(&self.fd, self.state.recv_raw()).await
            }
        }

        impl $blocking {
            /// Register the socket with an async runtime.
            pub fn into_async<R: Runtime>(self) -> io::Result<$async<R>> {
                let (fd, state) = self.into_parts();
                Ok($async {
                    fd: R::register(fd)?,
                    state,
                })
            }
        }

        impl<R: Runtime> AsFd for $async<R> {
            fn as_fd(&self) -> BorrowedFd<'_> {
                self.fd.as_fd()
            }
        }

        impl<R: Runtime> AsRawFd for $async<R> {
            fn as_raw_fd(&self) -> RawFd {
                self.fd.as_fd().as_raw_fd()
            }
        }
    };
}

/// The send methods of an async raw socket.
macro_rules! async_raw_send {
    ($async:ident, addr = $addr:ty, msg = $msg:ty) => {
        impl<R: Runtime> $async<R> {
            /// Send a message.
            pub async fn send_to(&mut self, dest: impl Into<$addr>, msg: &$msg) -> io::Result<()> {
                self.send_to_with_options(dest, msg, &SendOptions::new())
                    .await
            }

            /// Send a message with options for this send only.
            pub async fn send_to_with_options(
                &mut self,
                dest: impl Into<$addr>,
                msg: &$msg,
                opts: &SendOptions,
            ) -> io::Result<()> {
                let machine = self.state.send_to_with_options(dest, msg, opts);
                drive::<R, _>(&self.fd, machine).await
            }

            /// Send ICMP bytes as given.
            pub async fn send_raw(
                &mut self,
                dest: impl Into<$addr>,
                bytes: &[u8],
            ) -> io::Result<()> {
                self.send_raw_with_options(dest, bytes, &SendOptions::new())
                    .await
            }

            /// Send ICMP bytes as given, with options for this send only.
            pub async fn send_raw_with_options(
                &mut self,
                dest: impl Into<$addr>,
                bytes: &[u8],
                opts: &SendOptions,
            ) -> io::Result<()> {
                let machine = self.state.send_raw_with_options(dest, bytes, opts);
                drive::<R, _>(&self.fd, machine).await
            }
        }
    };
}

/// The send methods of an async datagram socket.
macro_rules! async_dgram_send {
    ($async:ident, addr = $addr:ty) => {
        impl<R: Runtime> $async<R> {
            /// Send an echo request. The socket supplies the identifier.
            pub async fn send_echo(
                &mut self,
                dest: impl Into<$addr>,
                sequence: u16,
                payload: &[u8],
            ) -> io::Result<()> {
                self.send_echo_with_options(dest, sequence, payload, &SendOptions::new())
                    .await
            }

            /// Send an echo request with options for this send only.
            pub async fn send_echo_with_options(
                &mut self,
                dest: impl Into<$addr>,
                sequence: u16,
                payload: &[u8],
                opts: &SendOptions,
            ) -> io::Result<()> {
                let machine = self
                    .state
                    .send_echo_with_options(dest, sequence, payload, opts);
                drive::<R, _>(&self.fd, machine).await
            }

            /// The ICMP identifier this socket's echo requests carry; see
            /// the blocking socket's `identifier`.
            pub fn identifier(&self) -> u16 {
                crate::state::dgram_identifier(self.fd.as_fd())
            }
        }
    };
}

/// An async raw ICMPv4 socket. See [`RawSocket4`].
pub struct AsyncRawSocket4<R: Runtime> {
    fd: R::Registered,
    state: RawState4,
}

/// An async raw ICMPv6 socket. See [`RawSocket6`].
pub struct AsyncRawSocket6<R: Runtime> {
    fd: R::Registered,
    state: RawState6,
}

/// An async datagram ICMPv4 socket. See [`DgramSocket4`].
pub struct AsyncDgramSocket4<R: Runtime> {
    fd: R::Registered,
    state: DgramState4,
}

/// An async datagram ICMPv6 socket. See [`DgramSocket6`].
pub struct AsyncDgramSocket6<R: Runtime> {
    fd: R::Registered,
    state: DgramState6,
}

async_common!(
    AsyncRawSocket4,
    RawSocket4,
    RawState4,
    addr = Ipv4Addr,
    msg = Icmpv4Message,
    proto = Ipv4RecvError,
    local = local_v4
);
async_raw_send!(AsyncRawSocket4, addr = Ipv4Addr, msg = Icmpv4Message);

async_common!(
    AsyncRawSocket6,
    RawSocket6,
    RawState6,
    addr = ScopedIpv6Addr,
    msg = Icmpv6Message,
    proto = Infallible,
    local = local_v6
);
async_raw_send!(AsyncRawSocket6, addr = ScopedIpv6Addr, msg = Icmpv6Message);

async_common!(
    AsyncDgramSocket4,
    DgramSocket4,
    DgramState4,
    addr = Ipv4Addr,
    msg = Icmpv4Message,
    proto = Ipv4RecvError,
    local = local_v4
);
async_dgram_send!(AsyncDgramSocket4, addr = Ipv4Addr);

async_common!(
    AsyncDgramSocket6,
    DgramSocket6,
    DgramState6,
    addr = ScopedIpv6Addr,
    msg = Icmpv6Message,
    proto = Infallible,
    local = local_v6
);
async_dgram_send!(AsyncDgramSocket6, addr = ScopedIpv6Addr);
