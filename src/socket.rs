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
//! Blocking ICMP sockets.
//!
//! There are four kinds: raw or datagram, ICMPv4 or ICMPv6.
//!
//! - **Raw** sockets ([`RawSocket4`], [`RawSocket6`]) send any message and
//!   receive every ICMP packet for the host. They need root, or
//!   `CAP_NET_RAW` on Linux.
//! - **Datagram** ("ping") sockets ([`DgramSocket4`], [`DgramSocket6`]) send
//!   only echo requests and own their identifier. They need no privileges
//!   on macOS, and on Linux when `net.ipv4.ping_group_range` includes the
//!   user's group.
//!
//! Every socket behaves the same on every supported system; the crate hides
//! the differences between the kernels.
use std::convert::Infallible;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

use socket2::{SockRef, Socket, Type};

use crate::addr::ScopedIpv6Addr;
use crate::error::{Ipv4RecvError, RecvError};
use crate::filter::TypeFilter;
use crate::machine::{Machine, Next, Operation};
use crate::state::{Core, Family, Parsed, ParsedFrom, Payload, Raw, RecvInfo, SendOptions, V4, V6};
use crate::sys;
use crate::{Icmpv4Message, Icmpv6Message};

/// Run a machine to completion on a non-blocking descriptor, waiting with
/// `poll`. `timeout` limits the waits for reading.
fn drive<M: Machine>(fd: BorrowedFd<'_>, timeout: Option<Duration>, mut machine: M) -> M::Output {
    let deadline = timeout.map(|t| Instant::now() + t);
    loop {
        match machine.next() {
            Next::Done(out) => return out,
            Next::Io(Operation::None) => {
                machine.perform(fd);
            }
            Next::Io(operation) => {
                let limit = match (operation, deadline) {
                    (Operation::Read, Some(deadline)) => {
                        Some(deadline.saturating_duration_since(Instant::now()))
                    }
                    _ => None,
                };
                match sys::poll(fd, operation, limit) {
                    Ok(true) => {
                        machine.perform(fd);
                    }
                    Ok(false) => machine.fail(io::ErrorKind::TimedOut.into()),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => machine.fail(e),
                }
            }
        }
    }
}

fn open<F: Family>(ty: Type) -> io::Result<OwnedFd> {
    let socket = Socket::new(F::DOMAIN, ty, Some(F::PROTOCOL))?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

fn local_v4(fd: BorrowedFd<'_>) -> io::Result<Ipv4Addr> {
    match SockRef::from(&fd).local_addr()?.as_socket() {
        Some(SocketAddr::V4(a)) => Ok(*a.ip()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "socket has no IPv4 address",
        )),
    }
}

fn local_v6(fd: BorrowedFd<'_>) -> io::Result<ScopedIpv6Addr> {
    match SockRef::from(&fd).local_addr()?.as_socket() {
        Some(SocketAddr::V6(a)) => Ok(a.into()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "socket has no IPv6 address",
        )),
    }
}

/// Reject a zero timeout, as std's sockets do.
fn check_timeout(t: Option<Duration>) -> io::Result<()> {
    if t == Some(Duration::ZERO) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a zero read timeout is not allowed",
        ));
    }
    Ok(())
}

/// The methods every socket kind has.
macro_rules! socket_common {
    (
        $socket:ident, $state:ident, $family:ty, $raw:expr, $ty:expr,
        addr = $addr:ty, msg = $msg:ty, proto = $proto:ty, local = $local:path
    ) => {
        impl $socket {
            /// Open an unbound socket. The kernel chooses the local address
            /// for each destination, and binds a datagram socket on its first
            /// send.
            pub fn open() -> io::Result<Self> {
                let fd = open::<$family>($ty)?;
                let state = $state {
                    core: Core::new(fd.as_fd(), $raw)?,
                };
                Ok(Self {
                    fd,
                    state,
                    read_timeout: None,
                })
            }

            /// Open a socket bound to a local address.
            pub fn bind(addr: impl Into<$addr>) -> io::Result<Self> {
                let socket = Self::open()?;
                SockRef::from(&socket.fd).bind(&<$family as Family>::sockaddr(addr.into()))?;
                Ok(socket)
            }

            /// The local address, as the kernel reports it.
            pub fn local_addr(&self) -> io::Result<$addr> {
                $local(self.fd.as_fd())
            }

            /// Limit how long a receive waits. `None` waits forever. When the
            /// timeout expires, a receive fails with [`RecvError::Timeout`].
            /// A zero duration is an error.
            pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
                check_timeout(timeout)?;
                self.read_timeout = timeout;
                Ok(())
            }

            pub fn read_timeout(&self) -> Option<Duration> {
                self.read_timeout
            }

            /// The largest message a receive accepts (default 2048 bytes).
            /// A larger message fails with [`RecvError::Truncated`].
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
            pub fn recv_from(&mut self) -> Result<($msg, $addr), RecvError<$proto>> {
                drive(self.fd.as_fd(), self.read_timeout, self.state.recv_from())
            }

            /// Receive a message and facts about its packet.
            pub fn recv_with_info(&mut self) -> Result<($msg, RecvInfo<$addr>), RecvError<$proto>> {
                drive(
                    self.fd.as_fd(),
                    self.read_timeout,
                    self.state.recv_with_info(),
                )
            }

            /// Receive a message as ICMP bytes (no IP header), without
            /// parsing it or checking its checksum. The bytes stay valid until
            /// the next receive.
            pub fn recv_raw(&mut self) -> Result<(&[u8], RecvInfo<$addr>), RecvError<$proto>> {
                drive(self.fd.as_fd(), self.read_timeout, self.state.recv_raw())
            }

            /// Split the socket into its descriptor (non-blocking) and its
            /// I/O-free state, to drive the state's machines with another
            /// runtime. See [`crate::machine`].
            pub fn into_parts(self) -> (OwnedFd, $state) {
                (self.fd, self.state)
            }

            /// Join parts from [`Self::into_parts`] again. The descriptor must
            /// be non-blocking and come from the same kind of socket.
            pub fn from_parts(fd: OwnedFd, state: $state) -> Self {
                Self {
                    fd,
                    state,
                    read_timeout: None,
                }
            }
        }

        impl AsFd for $socket {
            fn as_fd(&self) -> BorrowedFd<'_> {
                self.fd.as_fd()
            }
        }

        impl AsRawFd for $socket {
            fn as_raw_fd(&self) -> RawFd {
                self.fd.as_raw_fd()
            }
        }

        impl From<$socket> for OwnedFd {
            fn from(socket: $socket) -> OwnedFd {
                socket.fd
            }
        }

        impl $state {
            /// See the socket's `set_max_message_size`.
            pub fn set_max_message_size(&mut self, size: usize) {
                self.core.set_max_message_size(size);
            }

            /// See the socket's `set_type_filter`. `fd` is the socket's
            /// descriptor.
            pub fn set_type_filter(
                &mut self,
                fd: BorrowedFd<'_>,
                filter: &TypeFilter,
            ) -> io::Result<()> {
                self.core.set_type_filter(fd, filter)
            }

            /// The machine for a `recv_from`.
            pub fn recv_from(
                &mut self,
            ) -> impl Machine<Output = Result<($msg, $addr), RecvError<$proto>>> + '_ {
                self.core.recv::<ParsedFrom>()
            }

            /// The machine for a `recv_with_info`.
            pub fn recv_with_info(
                &mut self,
            ) -> impl Machine<Output = Result<($msg, RecvInfo<$addr>), RecvError<$proto>>> + '_
            {
                self.core.recv::<Parsed>()
            }

            /// The machine for a `recv_raw`.
            pub fn recv_raw(
                &mut self,
            ) -> impl Machine<Output = Result<(&[u8], RecvInfo<$addr>), RecvError<$proto>>> + '_
            {
                self.core.recv::<Raw>()
            }
        }
    };
}

/// The send methods of a raw socket.
macro_rules! raw_send {
    ($socket:ident, $state:ident, addr = $addr:ty, msg = $msg:ty) => {
        impl $socket {
            /// Send a message.
            pub fn send_to(&mut self, dest: impl Into<$addr>, msg: &$msg) -> io::Result<()> {
                self.send_to_with_options(dest, msg, &SendOptions::new())
            }

            /// Send a message with options for this send only.
            pub fn send_to_with_options(
                &mut self,
                dest: impl Into<$addr>,
                msg: &$msg,
                opts: &SendOptions,
            ) -> io::Result<()> {
                drive(
                    self.fd.as_fd(),
                    None,
                    self.state.send_to_with_options(dest, msg, opts),
                )
            }

            /// Send ICMP bytes as given, e.g. a deliberately malformed
            /// message.
            pub fn send_raw(&mut self, dest: impl Into<$addr>, bytes: &[u8]) -> io::Result<()> {
                self.send_raw_with_options(dest, bytes, &SendOptions::new())
            }

            /// Send ICMP bytes as given, with options for this send only.
            pub fn send_raw_with_options(
                &mut self,
                dest: impl Into<$addr>,
                bytes: &[u8],
                opts: &SendOptions,
            ) -> io::Result<()> {
                drive(
                    self.fd.as_fd(),
                    None,
                    self.state.send_raw_with_options(dest, bytes, opts),
                )
            }
        }

        impl $state {
            /// The machine for a `send_to`.
            pub fn send_to<'a>(
                &'a mut self,
                dest: impl Into<$addr>,
                msg: &'a $msg,
            ) -> impl Machine<Output = io::Result<()>> + 'a {
                self.core
                    .send(dest.into(), Payload::Message(msg), &SendOptions::new())
            }

            /// The machine for a `send_to_with_options`.
            pub fn send_to_with_options<'a>(
                &'a mut self,
                dest: impl Into<$addr>,
                msg: &'a $msg,
                opts: &SendOptions,
            ) -> impl Machine<Output = io::Result<()>> + 'a {
                self.core.send(dest.into(), Payload::Message(msg), opts)
            }

            /// The machine for a `send_raw_with_options`.
            pub fn send_raw_with_options<'a>(
                &'a mut self,
                dest: impl Into<$addr>,
                bytes: &'a [u8],
                opts: &SendOptions,
            ) -> impl Machine<Output = io::Result<()>> + 'a {
                self.core.send(dest.into(), Payload::Raw(bytes), opts)
            }
        }
    };
}

/// The send methods of a datagram socket.
macro_rules! dgram_send {
    ($socket:ident, $state:ident, addr = $addr:ty) => {
        impl $socket {
            /// Send an echo request. The socket supplies the identifier.
            pub fn send_echo(
                &mut self,
                dest: impl Into<$addr>,
                sequence: u16,
                payload: &[u8],
            ) -> io::Result<()> {
                self.send_echo_with_options(dest, sequence, payload, &SendOptions::new())
            }

            /// Send an echo request with options for this send only.
            pub fn send_echo_with_options(
                &mut self,
                dest: impl Into<$addr>,
                sequence: u16,
                payload: &[u8],
                opts: &SendOptions,
            ) -> io::Result<()> {
                drive(
                    self.fd.as_fd(),
                    None,
                    self.state
                        .send_echo_with_options(dest, sequence, payload, opts),
                )
            }

            /// The ICMP identifier this socket's echo requests carry. Match
            /// replies against it.
            ///
            /// On Linux this is the socket's local port, which the kernel
            /// assigns at `bind` or at the first send; it is 0 before that.
            /// On macOS it is the low 16 bits of the process ID, as macOS
            /// `ping` uses, so two sockets in one process share it, and every
            /// datagram ICMP socket receives every reply: filter replies by
            /// identifier and sequence.
            pub fn identifier(&self) -> u16 {
                crate::state::dgram_identifier(self.fd.as_fd())
            }
        }

        impl $state {
            /// The machine for a `send_echo_with_options`.
            pub fn send_echo_with_options<'a>(
                &'a mut self,
                dest: impl Into<$addr>,
                sequence: u16,
                payload: &'a [u8],
                opts: &SendOptions,
            ) -> impl Machine<Output = io::Result<()>> + 'a {
                self.core
                    .send(dest.into(), Payload::Echo { sequence, payload }, opts)
            }
        }
    };
}

/// A raw ICMPv4 socket. Needs root, or `CAP_NET_RAW` on Linux.
pub struct RawSocket4 {
    fd: OwnedFd,
    state: RawState4,
    read_timeout: Option<Duration>,
}

/// The I/O-free state of a [`RawSocket4`]; see [`crate::machine`].
pub struct RawState4 {
    core: Core<V4>,
}

/// A raw ICMPv6 socket. Needs root, or `CAP_NET_RAW` on Linux.
///
/// The kernel computes the checksum of every message sent and verifies it on
/// every message received (RFC 3542 section 3.1).
///
/// A link-local destination with scope 0 behaves differently per system:
/// macOS fails the send with `EHOSTUNREACH`, and Linux sends on an interface
/// its routing table picks. Give a scope ID for the same behavior on both.
pub struct RawSocket6 {
    fd: OwnedFd,
    state: RawState6,
    read_timeout: Option<Duration>,
}

/// The I/O-free state of a [`RawSocket6`]; see [`crate::machine`].
pub struct RawState6 {
    core: Core<V6>,
}

/// A datagram ("ping") ICMPv4 socket. Sends echo requests only.
pub struct DgramSocket4 {
    fd: OwnedFd,
    state: DgramState4,
    read_timeout: Option<Duration>,
}

/// The I/O-free state of a [`DgramSocket4`]; see [`crate::machine`].
pub struct DgramState4 {
    core: Core<V4>,
}

socket_common!(
    RawSocket4,
    RawState4,
    V4,
    true,
    Type::RAW,
    addr = Ipv4Addr,
    msg = Icmpv4Message,
    proto = Ipv4RecvError,
    local = local_v4
);
raw_send!(RawSocket4, RawState4, addr = Ipv4Addr, msg = Icmpv4Message);

socket_common!(
    RawSocket6,
    RawState6,
    V6,
    true,
    Type::RAW,
    addr = ScopedIpv6Addr,
    msg = Icmpv6Message,
    proto = Infallible,
    local = local_v6
);
raw_send!(
    RawSocket6,
    RawState6,
    addr = ScopedIpv6Addr,
    msg = Icmpv6Message
);

socket_common!(
    DgramSocket4,
    DgramState4,
    V4,
    false,
    Type::DGRAM,
    addr = Ipv4Addr,
    msg = Icmpv4Message,
    proto = Ipv4RecvError,
    local = local_v4
);
dgram_send!(DgramSocket4, DgramState4, addr = Ipv4Addr);

/// A datagram ("ping") ICMPv6 socket. Sends echo requests only.
///
/// A link-local destination with scope 0 behaves differently per system:
/// macOS fails the send with `EHOSTUNREACH`, and Linux sends on an interface
/// its routing table picks. Give a scope ID for the same behavior on both.
pub struct DgramSocket6 {
    fd: OwnedFd,
    state: DgramState6,
    read_timeout: Option<Duration>,
}

/// The I/O-free state of a [`DgramSocket6`]; see [`crate::machine`].
pub struct DgramState6 {
    core: Core<V6>,
}

socket_common!(
    DgramSocket6,
    DgramState6,
    V6,
    false,
    Type::DGRAM,
    addr = ScopedIpv6Addr,
    msg = Icmpv6Message,
    proto = Infallible,
    local = local_v6
);
dgram_send!(DgramSocket6, DgramState6, addr = ScopedIpv6Addr);
