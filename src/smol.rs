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
//! Async ICMP socket implementations built on the [`smol`] runtime.
//!
//! This module is gated behind the `smol` feature. Obtain an async socket by
//! constructing a [`crate::IcmpSocket4`] or [`crate::DgramIcmpSocket4`] and
//! calling `into_async`.
use std::{net::Ipv4Addr, time::Duration};

use async_trait::async_trait;
use smol::{Async, Timer, future::FutureExt};
use socket2::{SockAddr, Socket};

use crate::{
    Icmpv4Message,
    socket::{
        Core, Family, SockOpts, V4, decode_received, dgram_identifier, recv_into, timed_out_error,
        to_sockaddr,
    },
};

/// Shared low-level state and operations for the async sockets, mirroring
/// the blocking `Core` but driven through the smol reactor.
struct AsyncCore<F: Family> {
    inner: Async<Socket>,
    bound_to: Option<F::Addr>,
    buf: Vec<u8>,
    buf_size: usize,
    opts: SockOpts,
}

impl<F: Family> AsyncCore<F> {
    fn new(core: Core<F>) -> std::io::Result<Self> {
        Ok(Self {
            inner: Async::new(core.inner)?,
            bound_to: core.bound_to,
            buf: core.buf,
            buf_size: core.buf_size,
            opts: core.opts,
        })
    }

    fn bind(&mut self, addr: F::Addr) -> std::io::Result<()> {
        self.bound_to = Some(addr);
        // Binding does not block, so it is safe to call directly on the
        // underlying descriptor.
        self.inner.get_ref().bind(&to_sockaddr(addr))
    }

    fn set_read_buffer_size(&mut self, size: usize) {
        self.buf_size = size;
    }

    async fn send_bytes(&mut self, dest: F::Addr, bytes: &[u8]) -> std::io::Result<()> {
        self.opts.apply_hops::<F>(self.inner.get_ref())?;
        let dest = to_sockaddr(dest);
        self.inner
            .write_with(|sock| sock.send_to(bytes, &dest))
            .await?;
        Ok(())
    }

    async fn recv(&mut self) -> std::io::Result<(F::Packet, SockAddr)> {
        let timeout = self.opts.timeout;
        let inner = &self.inner;
        let buf = &mut self.buf;
        let buf_size = self.buf_size;
        let recv = inner.read_with(|sock| recv_into(sock, buf, buf_size));
        let received = match timeout {
            Some(t) => {
                recv.or(async move {
                    Timer::after(t).await;
                    Err(timed_out_error())
                })
                .await?
            }
            None => recv.await?,
        };
        Ok((
            decode_received::<F>(&self.buf, received.truncated)?,
            received.addr,
        ))
    }
}

/// An async raw (SOCK_RAW) ICMPv4 socket driven by the smol reactor.
pub struct AsyncIcmpV4Socket {
    core: AsyncCore<V4>,
}

impl AsyncIcmpV4Socket {
    /// Wrap a blocking socket in the smol reactor. Construct one via
    /// [`crate::IcmpSocket4::into_async`].
    pub(crate) fn new(core: Core<V4>) -> std::io::Result<Self> {
        Ok(Self {
            core: AsyncCore::new(core)?,
        })
    }

    /// The address this socket has been bound to, if any.
    pub fn bound_to(&self) -> Option<Ipv4Addr> {
        self.core.bound_to
    }

    /// Set the size of the per-read receive buffer (default 2048 bytes). A
    /// packet larger than this is truncated on read, and `rcv_from` reports the
    /// truncation rather than returning a partial packet.
    pub fn set_read_buffer_size(&mut self, size: usize) {
        self.core.set_read_buffer_size(size);
    }
}

#[async_trait]
pub trait AsyncIcmpSocket {
    /// The type of address this socket operates on.
    type AddrType;
    /// The type of packet this socket handles.
    type PacketType;

    /// Sets the timeout on the socket for `rcv_from`. A value of None
    /// will cause `rcv_from` to wait indefinitely. When the timeout expires,
    /// `rcv_from` returns an error of kind `TimedOut`.
    fn set_timeout(&mut self, timeout: Option<Duration>);

    /// Sets the ttl for packets sent on this socket. Controls the number of
    /// hops the packet will be allowed to traverse. Until it is called, the
    /// OS default applies.
    fn set_max_hops(&mut self, hops: u32);

    /// Binds this socket to an address.
    async fn bind<A: Into<Self::AddrType> + Send>(&mut self, addr: A) -> std::io::Result<()>;

    /// Sends the packet to the given destination.
    async fn send_to(
        &mut self,
        dest: Self::AddrType,
        packet: Self::PacketType,
    ) -> std::io::Result<()>;

    /// Receive a packet on this socket.
    async fn rcv_from(&mut self) -> std::io::Result<(Self::PacketType, SockAddr)>;
}

#[async_trait]
impl AsyncIcmpSocket for AsyncIcmpV4Socket {
    type AddrType = Ipv4Addr;
    type PacketType = Icmpv4Message;

    fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.core.opts.timeout = timeout;
    }

    fn set_max_hops(&mut self, hops: u32) {
        self.core.opts.hops = Some(hops);
    }

    async fn bind<A: Into<Self::AddrType> + Send>(&mut self, addr: A) -> std::io::Result<()> {
        self.core.bind(addr.into())
    }

    async fn send_to(
        &mut self,
        dest: Self::AddrType,
        packet: Self::PacketType,
    ) -> std::io::Result<()> {
        self.core.send_bytes(dest, &packet.to_bytes()).await
    }

    async fn rcv_from(&mut self) -> std::io::Result<(Self::PacketType, SockAddr)> {
        self.core.recv().await
    }
}

/// An async datagram (SOCK_DGRAM) ICMPv4 "ping" socket driven by the smol
/// reactor. Like the blocking [`crate::DgramIcmpSocket4`], it owns the
/// identifier rather than taking it from the caller, so [`Self::send`] takes
/// only the sequence and payload.
pub struct AsyncDgramIcmpV4Socket {
    core: AsyncCore<V4>,
}

impl AsyncDgramIcmpV4Socket {
    /// Construct one via [`crate::DgramIcmpSocket4::into_async`].
    pub(crate) fn new(core: Core<V4>) -> std::io::Result<Self> {
        Ok(Self {
            core: AsyncCore::new(core)?,
        })
    }

    /// The address this socket has been bound to, if any.
    pub fn bound_to(&self) -> Option<Ipv4Addr> {
        self.core.bound_to
    }

    /// Set the size of the per-read receive buffer (default 2048 bytes). A
    /// packet larger than this is truncated on read, and `rcv_from` reports the
    /// truncation rather than returning a partial packet.
    pub fn set_read_buffer_size(&mut self, size: usize) {
        self.core.set_read_buffer_size(size);
    }

    /// The ICMP identifier this socket uses on the wire. Match replies against
    /// it. It is chosen as described for
    /// [`crate::DgramIcmpSocket4::identifier`].
    pub fn identifier(&self) -> u16 {
        dgram_identifier(self.core.inner.get_ref())
    }

    /// Sets the timeout on the socket for `rcv_from`. A value of None blocks.
    /// When the timeout expires, `rcv_from` returns an error of kind
    /// `TimedOut`.
    pub fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.core.opts.timeout = timeout;
    }

    /// Sets the ttl for packets sent on this socket. Until it is called, the
    /// OS default applies.
    pub fn set_max_hops(&mut self, hops: u32) {
        self.core.opts.hops = Some(hops);
    }

    /// Bind the socket to a local address.
    pub async fn bind<A: Into<Ipv4Addr>>(&mut self, addr: A) -> std::io::Result<()> {
        self.core.bind(addr.into())
    }

    /// Send an echo request to `dest`. The identifier is supplied by the socket,
    /// so the caller provides only the sequence number and payload.
    pub async fn send(
        &mut self,
        dest: Ipv4Addr,
        sequence: u16,
        payload: Vec<u8>,
    ) -> std::io::Result<()> {
        let packet = Icmpv4Message::echo_request(self.identifier(), sequence, payload);
        self.core.send_bytes(dest, &packet.to_bytes()).await
    }

    /// Receive a packet. Replies are not filtered; compare against
    /// [`Self::identifier`] to select those belonging to this socket.
    pub async fn rcv_from(&mut self) -> std::io::Result<(Icmpv4Message, SockAddr)> {
        self.core.recv().await
    }
}
