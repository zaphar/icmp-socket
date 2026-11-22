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
//! ICMP Socket implementations for both ICMP4 and ICMP6 protocols.
//!
//! There is a common IcmpSocket trait implemented for both the v4 and v6 protocols.
//! The socket is associated to both an address type and packet type.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::{
    convert::{Into, TryFrom},
    time::Duration,
};

use socket2::{Domain, MaybeUninitSlice, Protocol, SockAddr, Socket, Type};

use crate::packet::{Icmpv4Packet, Icmpv6Packet, PacketParseError, WithEchoRequest};

pub fn ip_to_socket(ip: &IpAddr) -> SocketAddr {
    SocketAddr::new(*ip, 0)
}

/// Trait for an IcmpSocket implemented by Icmpv4Socket and Icmpv6Socket.
pub trait IcmpSocket {
    /// The type of address this socket operates on.
    type AddrType;
    /// The type of packet this socket handles.
    type PacketType;

    /// Sets the timeout on the socket for rcv_from. A value of None
    /// will cause rcv_from to block.
    fn set_timeout(&mut self, timeout: Option<Duration>);

    /// Sets the ttl for packets sent on this socket. Controls the number of
    /// hops the packet will be allowed to traverse.
    fn set_max_hops(&mut self, hops: u32);

    /// Binds this socket to an address.
    fn bind<A: Into<Self::AddrType>>(&mut self, addr: A) -> std::io::Result<()>;

    /// Sends the packet to the given destination.
    fn send_to(&mut self, dest: Self::AddrType, packet: Self::PacketType) -> std::io::Result<()>;

    /// Receive a packet on this socket.
    fn rcv_from(&mut self) -> std::io::Result<(Self::PacketType, SockAddr)>;
}

/// Options for this socket.
pub struct Opts {
    pub hops: u32,
    pub timeout: Option<Duration>,
}

/// Default size of the per-read receive buffer. It holds a reply on a
/// typical Ethernet MTU. Larger replies need a bigger buffer via
/// `set_read_buffer_size`.
const DEFAULT_RECV_BUFFER_SIZE: usize = 2048;

/// The differences between ICMPv4 and ICMPv6 that the socket core needs.
pub(crate) trait Family {
    const DOMAIN: Domain;
    const PROTOCOL: Protocol;
    type Addr: Copy + Into<IpAddr>;
    type Packet;

    /// Set the hop limit (TTL) for unicast packets.
    fn set_hops(sock: &Socket, hops: u32) -> std::io::Result<()>;

    /// Decode a received message. Whether it starts with an IP header
    /// depends on the protocol, the OS and the socket type.
    fn decode(bytes: &[u8]) -> Result<Self::Packet, PacketParseError>;
}

pub(crate) enum V4 {}

impl Family for V4 {
    const DOMAIN: Domain = Domain::IPV4;
    const PROTOCOL: Protocol = Protocol::ICMPV4;
    type Addr = Ipv4Addr;
    type Packet = Icmpv4Packet;

    fn set_hops(sock: &Socket, hops: u32) -> std::io::Result<()> {
        sock.set_ttl(hops)
    }

    fn decode(bytes: &[u8]) -> Result<Icmpv4Packet, PacketParseError> {
        // Whether an IPv4 header is present depends on the OS and socket
        // type, so detect it from the bytes rather than assuming.
        Icmpv4Packet::parse_auto(bytes)
    }
}

pub(crate) enum V6 {}

impl Family for V6 {
    const DOMAIN: Domain = Domain::IPV6;
    const PROTOCOL: Protocol = Protocol::ICMPV6;
    type Addr = Ipv6Addr;
    type Packet = Icmpv6Packet;

    fn set_hops(sock: &Socket, hops: u32) -> std::io::Result<()> {
        sock.set_unicast_hops_v6(hops)
    }

    fn decode(bytes: &[u8]) -> Result<Icmpv6Packet, PacketParseError> {
        // IPv6 sockets never deliver the IPv6 header.
        Icmpv6Packet::parse(bytes)
    }
}

/// The socket address for an IP address. ICMP has no ports, so the port is 0.
pub(crate) fn to_sockaddr<A: Into<IpAddr>>(addr: A) -> SockAddr {
    ip_to_socket(&addr.into()).into()
}

/// The bound local port of a socket. On a datagram (ping) socket this is the
/// ICMP identifier the kernel associates with the socket.
pub(crate) fn local_port(sock: &Socket) -> std::io::Result<u16> {
    let addr = sock.local_addr()?;
    Ok(addr.as_socket().map(|s| s.port()).unwrap_or(0))
}

/// One message read by [`recv_into`].
pub(crate) struct Received {
    pub(crate) addr: SockAddr,
    /// The kernel reported that the message was larger than the buffer.
    pub(crate) truncated: bool,
}

/// Receive one message into `buf`, which holds at most `size` bytes. On
/// return `buf` holds exactly the bytes received.
pub(crate) fn recv_into(
    sock: &Socket,
    buf: &mut Vec<u8>,
    size: usize,
) -> std::io::Result<Received> {
    buf.clear();
    buf.reserve(size);
    let mut bufs = [MaybeUninitSlice::new(&mut buf.spare_capacity_mut()[..size])];
    let (read_count, flags, addr) = sock.recv_from_vectored(&mut bufs)?;
    // SAFETY: `recv_from_vectored` initialized the first `read_count` bytes.
    unsafe { buf.set_len(read_count) };
    Ok(Received {
        addr,
        truncated: flags.is_truncated(),
    })
}

/// Decode a received message, reporting a truncation instead of a partial
/// packet.
pub(crate) fn decode_received<F: Family>(
    received: &[u8],
    truncated: bool,
) -> std::io::Result<F::Packet> {
    if truncated {
        return Err(truncated_error());
    }
    Ok(F::decode(received)?)
}

/// Shared low-level state and operations for the blocking sockets. This keeps
/// the public socket types thin: they differ only in how a packet is sent,
/// not in binding, receiving, or option handling.
pub(crate) struct Core<F: Family> {
    pub(crate) inner: Socket,
    pub(crate) bound_to: Option<F::Addr>,
    /// The receive buffer. Its length is the size of the last message.
    pub(crate) buf: Vec<u8>,
    /// The largest message one read accepts.
    pub(crate) buf_size: usize,
    pub(crate) opts: Opts,
}

impl<F: Family> Core<F> {
    fn open(ty: Type) -> std::io::Result<Self> {
        Ok(Self {
            inner: Socket::new(F::DOMAIN, ty, Some(F::PROTOCOL))?,
            bound_to: None,
            buf: Vec::with_capacity(DEFAULT_RECV_BUFFER_SIZE),
            buf_size: DEFAULT_RECV_BUFFER_SIZE,
            opts: Opts {
                hops: 50,
                timeout: None,
            },
        })
    }

    fn bind(&mut self, addr: F::Addr) -> std::io::Result<()> {
        self.bound_to = Some(addr);
        self.inner.bind(&to_sockaddr(addr))
    }

    fn set_read_buffer_size(&mut self, size: usize) {
        self.buf_size = size;
    }

    fn send_bytes(&self, dest: F::Addr, bytes: &[u8]) -> std::io::Result<()> {
        F::set_hops(&self.inner, self.opts.hops)?;
        self.inner.send_to(bytes, &to_sockaddr(dest))?;
        Ok(())
    }

    fn recv(&mut self) -> std::io::Result<(F::Packet, SockAddr)> {
        self.inner.set_read_timeout(self.opts.timeout)?;
        let received = recv_into(&self.inner, &mut self.buf, self.buf_size)?;
        Ok((
            decode_received::<F>(&self.buf, received.truncated)?,
            received.addr,
        ))
    }
}

/// The error returned when a received packet was larger than the read buffer.
pub(crate) fn truncated_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Other,
        "received packet was larger than the read buffer and was truncated; \
         increase it with set_read_buffer_size",
    )
}

/// A raw (SOCK_RAW) ICMPv4 socket. Requires elevated privileges. The caller
/// constructs and owns the full packet, including its identifier.
pub struct IcmpSocket4 {
    core: Core<V4>,
}

impl IcmpSocket4 {
    /// Construct a new raw socket. The socket must be bound to an address using `bind`
    /// before it can be used to send and receive packets.
    pub fn new() -> std::io::Result<Self> {
        Ok(Self {
            core: Core::open(Type::RAW)?,
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

    #[cfg(feature = "smol")]
    pub fn into_async(self) -> std::io::Result<crate::smol::AsyncIcmpV4Socket> {
        crate::smol::AsyncIcmpV4Socket::new(self.core)
    }
}

impl IcmpSocket for IcmpSocket4 {
    type AddrType = Ipv4Addr;
    type PacketType = Icmpv4Packet;

    fn set_max_hops(&mut self, hops: u32) {
        self.core.opts.hops = hops;
    }

    fn bind<A: Into<Self::AddrType>>(&mut self, addr: A) -> std::io::Result<()> {
        self.core.bind(addr.into())
    }

    fn send_to(&mut self, dest: Self::AddrType, packet: Self::PacketType) -> std::io::Result<()> {
        self.core
            .send_bytes(dest, &packet.with_checksum().get_bytes(true))
    }

    fn rcv_from(&mut self) -> std::io::Result<(Self::PacketType, SockAddr)> {
        self.core.recv()
    }

    fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.core.opts.timeout = timeout;
    }
}

/// A datagram (SOCK_DGRAM) ICMPv4 "ping" socket. Usable without elevated
/// privileges where the OS permits it (macOS, and Linux when
/// `net.ipv4.ping_group_range` includes the running user's gid).
///
/// Unlike the raw socket, the identifier is not the caller's to choose: on
/// Linux the kernel overwrites the packet's identifier with the socket's local
/// port. This type therefore owns the identifier — derived from the bound port
/// and reported by [`Self::identifier`] — and its [`Self::send`] takes only the
/// sequence and payload. Match replies against [`Self::identifier`].
pub struct DgramIcmpSocket4 {
    core: Core<V4>,
    identifier: u16,
}

impl DgramIcmpSocket4 {
    /// Construct a new datagram socket. It must be bound with [`Self::bind`]
    /// before sending so that its identifier is established.
    pub fn new() -> std::io::Result<Self> {
        Ok(Self {
            core: Core::open(Type::DGRAM)?,
            identifier: 0,
        })
    }

    /// Bind the socket and establish its identifier from the assigned local
    /// port.
    pub fn bind<A: Into<Ipv4Addr>>(&mut self, addr: A) -> std::io::Result<()> {
        self.core.bind(addr.into())?;
        self.identifier = local_port(&self.core.inner)?;
        Ok(())
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

    /// The ICMP identifier this socket uses on the wire. Use it to match replies
    /// that belong to this socket. Meaningful only after [`Self::bind`].
    ///
    /// This is the bound local port. On Linux that is a unique kernel-assigned
    /// value; on macOS a datagram ICMP socket is not assigned a port, so this
    /// is `0` and is not unique across sockets.
    pub fn identifier(&self) -> u16 {
        self.identifier
    }

    /// Sets the ttl for packets sent on this socket.
    pub fn set_max_hops(&mut self, hops: u32) {
        self.core.opts.hops = hops;
    }

    /// Sets the timeout on the socket for `rcv_from`. A value of None blocks.
    pub fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.core.opts.timeout = timeout;
    }

    /// Send an echo request to `dest`. The identifier is supplied by the socket,
    /// so the caller provides only the sequence number and payload.
    pub fn send(&mut self, dest: Ipv4Addr, sequence: u16, payload: Vec<u8>) -> std::io::Result<()> {
        let packet = Icmpv4Packet::with_echo_request(self.identifier, sequence, payload)?;
        self.core
            .send_bytes(dest, &packet.with_checksum().get_bytes(true))
    }

    /// Receive a packet. Replies are not filtered; compare against
    /// [`Self::identifier`] to select those belonging to this socket.
    pub fn rcv_from(&mut self) -> std::io::Result<(Icmpv4Packet, SockAddr)> {
        self.core.recv()
    }

    #[cfg(feature = "smol")]
    pub fn into_async(self) -> std::io::Result<crate::smol::AsyncDgramIcmpV4Socket> {
        crate::smol::AsyncDgramIcmpV4Socket::new(self.core, self.identifier)
    }
}

/// An Icmpv6 socket.
pub struct IcmpSocket6 {
    core: Core<V6>,
}

impl IcmpSocket6 {
    /// Construct a new raw socket. The socket must be bound to an address using `bind_to`
    /// before it can be used to send and receive packets.
    pub fn new() -> std::io::Result<Self> {
        Ok(Self {
            core: Core::open(Type::RAW)?,
        })
    }

    /// Set the size of the per-read receive buffer (default 2048 bytes). A
    /// packet larger than this is truncated on read, and `rcv_from` reports the
    /// truncation rather than returning a partial packet.
    pub fn set_read_buffer_size(&mut self, size: usize) {
        self.core.set_read_buffer_size(size);
    }
}

impl IcmpSocket for IcmpSocket6 {
    type AddrType = Ipv6Addr;
    type PacketType = Icmpv6Packet;

    fn set_max_hops(&mut self, hops: u32) {
        self.core.opts.hops = hops;
    }

    fn bind<A: Into<Self::AddrType>>(&mut self, addr: A) -> std::io::Result<()> {
        self.core.bind(addr.into())
    }

    fn send_to(
        &mut self,
        dest: Self::AddrType,
        mut packet: Self::PacketType,
    ) -> std::io::Result<()> {
        let source = match self.core.bound_to {
            Some(ref addr) => addr,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Socket not bound to an address",
                ))
            }
        };
        packet = packet.with_checksum(source, &dest);
        self.core.send_bytes(dest, &packet.get_bytes(true))
    }

    fn rcv_from(&mut self) -> std::io::Result<(Self::PacketType, SockAddr)> {
        self.core.recv()
    }

    fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.core.opts.timeout = timeout;
    }
}

impl TryFrom<Ipv4Addr> for IcmpSocket4 {
    type Error = std::io::Error;

    fn try_from(addr: Ipv4Addr) -> Result<Self, Self::Error> {
        let mut sock = IcmpSocket4::new()?;
        sock.bind(addr)?;
        Ok(sock)
    }
}

impl TryFrom<Ipv6Addr> for IcmpSocket6 {
    type Error = std::io::Error;

    fn try_from(addr: Ipv6Addr) -> Result<Self, Self::Error> {
        let mut sock = IcmpSocket6::new()?;
        sock.bind(addr)?;
        Ok(sock)
    }
}
