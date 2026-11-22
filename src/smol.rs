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
use std::{
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use async_trait::async_trait;
use smol::{future::FutureExt, Async, Timer};
use socket2::{SockAddr, Socket};

use crate::{
    packet::{Icmpv4Packet, WithEchoRequest},
    socket::{ip_to_socket, truncated_error, Opts},
};

/// Shared low-level state and operations for the async ICMPv4 sockets, mirroring
/// the blocking `Core` but driven through the smol reactor.
struct AsyncIcmp4Core {
    inner: Async<Socket>,
    bound_to: Option<Ipv4Addr>,
    buf: Vec<u8>,
    opts: Opts,
}

impl AsyncIcmp4Core {
    fn new(
        inner: Socket,
        bound_to: Option<Ipv4Addr>,
        buf: Vec<u8>,
        opts: Opts,
    ) -> std::io::Result<Self> {
        Ok(Self {
            inner: Async::new(inner)?,
            bound_to,
            buf,
            opts,
        })
    }

    fn bind(&mut self, addr: Ipv4Addr) -> std::io::Result<()> {
        self.bound_to = Some(addr);
        let sock = ip_to_socket(&IpAddr::V4(addr));
        // Binding does not block, so it is safe to call directly on the
        // underlying descriptor.
        self.inner.get_ref().bind(&(sock.into()))
    }

    fn local_identifier(&self) -> std::io::Result<u16> {
        let addr = self.inner.get_ref().local_addr()?;
        Ok(addr.as_socket_ipv4().map(|s| s.port()).unwrap_or(0))
    }

    fn set_read_buffer_size(&mut self, size: usize) {
        self.buf.resize(size, 0);
    }

    async fn send_bytes(&self, dest: Ipv4Addr, bytes: &[u8]) -> std::io::Result<()> {
        self.inner.get_ref().set_ttl(self.opts.hops)?;
        let dest: SockAddr = ip_to_socket(&IpAddr::V4(dest)).into();
        self.inner
            .write_with(|sock| sock.send_to(bytes, &dest))
            .await?;
        Ok(())
    }

    async fn recv(&mut self) -> std::io::Result<(Icmpv4Packet, SockAddr)> {
        let timeout = self.opts.timeout;
        let inner = &self.inner;
        let buf = &mut self.buf;
        // NOTE(jwall): the `recv_from` implementation promises not to write
        // uninitialised bytes to the buffer, so this cast is safe.
        let recv = async {
            let uninit =
                unsafe { &mut *(buf.as_mut_slice() as *mut [u8] as *mut [MaybeUninit<u8>]) };
            inner.read_with(|sock| sock.recv_from(uninit)).await
        };
        let (read_count, addr) = match timeout {
            Some(t) => {
                recv.or(async move {
                    Timer::after(t).await;
                    Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "rcv_from timed out",
                    ))
                })
                .await?
            }
            None => recv.await?,
        };
        // A full buffer means the packet may have been truncated on read.
        if read_count == self.buf.len() {
            return Err(truncated_error());
        }
        // Whether an IPv4 header is present depends on the OS and socket type,
        // so detect it from the bytes rather than assuming.
        let pkt = Icmpv4Packet::parse_auto(&self.buf[0..read_count])?;
        Ok((pkt, addr))
    }
}

/// An async raw (SOCK_RAW) ICMPv4 socket driven by the smol reactor.
pub struct AsyncIcmpV4Socket {
    core: AsyncIcmp4Core,
}

impl AsyncIcmpV4Socket {
    /// Wrap a blocking [`Socket`] in the smol reactor. Construct one via
    /// [`crate::IcmpSocket4::into_async`].
    pub(crate) fn new(
        inner: Socket,
        bound_to: Option<Ipv4Addr>,
        buf: Vec<u8>,
        opts: Opts,
    ) -> std::io::Result<Self> {
        Ok(Self {
            core: AsyncIcmp4Core::new(inner, bound_to, buf, opts)?,
        })
    }

    /// The address this socket has been bound to, if any.
    pub fn bound_to(&self) -> Option<Ipv4Addr> {
        self.core.bound_to
    }

    /// Set the size of the per-read receive buffer (default 2048 bytes). A
    /// packet larger than this is truncated on read, and `rcv_from` reports a
    /// possible truncation rather than returning a partial packet.
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
    /// will cause `rcv_from` to wait indefinitely.
    fn set_timeout(&mut self, timeout: Option<Duration>);

    /// Sets the ttl for packets sent on this socket. Controls the number of
    /// hops the packet will be allowed to traverse.
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
    type PacketType = Icmpv4Packet;

    fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.core.opts.timeout = timeout;
    }

    fn set_max_hops(&mut self, hops: u32) {
        self.core.opts.hops = hops;
    }

    async fn bind<A: Into<Self::AddrType> + Send>(&mut self, addr: A) -> std::io::Result<()> {
        self.core.bind(addr.into())
    }

    async fn send_to(
        &mut self,
        dest: Self::AddrType,
        packet: Self::PacketType,
    ) -> std::io::Result<()> {
        self.core
            .send_bytes(dest, &packet.with_checksum().get_bytes(true))
            .await
    }

    async fn rcv_from(&mut self) -> std::io::Result<(Self::PacketType, SockAddr)> {
        self.core.recv().await
    }
}

/// An async datagram (SOCK_DGRAM) ICMPv4 "ping" socket driven by the smol
/// reactor. Like the blocking [`crate::DgramIcmpSocket4`], it owns the
/// identifier (derived from the bound local port) rather than taking it from
/// the caller, so [`Self::send`] takes only the sequence and payload.
pub struct AsyncDgramIcmpV4Socket {
    core: AsyncIcmp4Core,
    identifier: u16,
}

impl AsyncDgramIcmpV4Socket {
    /// Construct one via [`crate::DgramIcmpSocket4::into_async`].
    pub(crate) fn new(
        inner: Socket,
        bound_to: Option<Ipv4Addr>,
        buf: Vec<u8>,
        opts: Opts,
        identifier: u16,
    ) -> std::io::Result<Self> {
        Ok(Self {
            core: AsyncIcmp4Core::new(inner, bound_to, buf, opts)?,
            identifier,
        })
    }

    /// The address this socket has been bound to, if any.
    pub fn bound_to(&self) -> Option<Ipv4Addr> {
        self.core.bound_to
    }

    /// Set the size of the per-read receive buffer (default 2048 bytes). A
    /// packet larger than this is truncated on read, and `rcv_from` reports a
    /// possible truncation rather than returning a partial packet.
    pub fn set_read_buffer_size(&mut self, size: usize) {
        self.core.set_read_buffer_size(size);
    }

    /// The ICMP identifier this socket uses on the wire. Match replies against
    /// it. Meaningful only after [`Self::bind`]. As with the blocking socket
    /// this is the bound local port, which is `0` on macOS (no port is
    /// assigned to a datagram ICMP socket there).
    pub fn identifier(&self) -> u16 {
        self.identifier
    }

    /// Sets the timeout on the socket for `rcv_from`. A value of None blocks.
    pub fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.core.opts.timeout = timeout;
    }

    /// Sets the ttl for packets sent on this socket.
    pub fn set_max_hops(&mut self, hops: u32) {
        self.core.opts.hops = hops;
    }

    /// Bind the socket and establish its identifier from the assigned local
    /// port.
    pub async fn bind<A: Into<Ipv4Addr>>(&mut self, addr: A) -> std::io::Result<()> {
        self.core.bind(addr.into())?;
        self.identifier = self.core.local_identifier()?;
        Ok(())
    }

    /// Send an echo request to `dest`. The identifier is supplied by the socket,
    /// so the caller provides only the sequence number and payload.
    pub async fn send(
        &mut self,
        dest: Ipv4Addr,
        sequence: u16,
        payload: Vec<u8>,
    ) -> std::io::Result<()> {
        let packet = Icmpv4Packet::with_echo_request(self.identifier, sequence, payload)?;
        self.core
            .send_bytes(dest, &packet.with_checksum().get_bytes(true))
            .await
    }

    /// Receive a packet. Replies are not filtered; compare against
    /// [`Self::identifier`] to select those belonging to this socket.
    pub async fn rcv_from(&mut self) -> std::io::Result<(Icmpv4Packet, SockAddr)> {
        self.core.recv().await
    }
}
