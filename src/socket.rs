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

use crate::{Icmpv4Message, Icmpv6Message};

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
    /// will cause rcv_from to block. When the timeout expires, rcv_from
    /// returns an error of kind `TimedOut`.
    fn set_timeout(&mut self, timeout: Option<Duration>);

    /// Sets the ttl for packets sent on this socket. Controls the number of
    /// hops the packet will be allowed to traverse. Until it is called, the
    /// OS default applies.
    fn set_max_hops(&mut self, hops: u32);

    /// Binds this socket to an address.
    fn bind<A: Into<Self::AddrType>>(&mut self, addr: A) -> std::io::Result<()>;

    /// Sends the packet to the given destination.
    fn send_to(&mut self, dest: Self::AddrType, packet: Self::PacketType) -> std::io::Result<()>;

    /// Receive a packet on this socket.
    fn rcv_from(&mut self) -> std::io::Result<(Self::PacketType, SockAddr)>;
}

/// Options for this socket.
#[deprecated(note = "not used by the sockets; set options with the socket methods")]
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
    fn decode(bytes: &[u8]) -> std::io::Result<Self::Packet>;
}

pub(crate) enum V4 {}

impl Family for V4 {
    const DOMAIN: Domain = Domain::IPV4;
    const PROTOCOL: Protocol = Protocol::ICMPV4;
    type Addr = Ipv4Addr;
    type Packet = Icmpv4Message;

    fn set_hops(sock: &Socket, hops: u32) -> std::io::Result<()> {
        sock.set_ttl_v4(hops)
    }

    fn decode(bytes: &[u8]) -> std::io::Result<Icmpv4Message> {
        // Whether an IPv4 header is present depends on the OS and socket
        // type, so detect it from the bytes rather than assuming.
        Ok(Icmpv4Message::parse(strip_ipv4_header(bytes)?)?)
    }
}

pub(crate) enum V6 {}

impl Family for V6 {
    const DOMAIN: Domain = Domain::IPV6;
    const PROTOCOL: Protocol = Protocol::ICMPV6;
    type Addr = Ipv6Addr;
    type Packet = Icmpv6Message;

    fn set_hops(sock: &Socket, hops: u32) -> std::io::Result<()> {
        sock.set_unicast_hops_v6(hops)
    }

    fn decode(bytes: &[u8]) -> std::io::Result<Icmpv6Message> {
        // IPv6 sockets never deliver the IPv6 header.
        Ok(Icmpv6Message::parse(bytes)?)
    }
}

/// Remove the IPv4 header if the bytes start with one.
///
/// Raw sockets always deliver the IPv4 header, Linux datagram sockets never
/// do, and macOS datagram sockets do. A valid IPv4 header starts with
/// version 4 and an IHL of at least 5 (`0x45..=0x4F`); no assigned ICMP type
/// is in that range, so an ICMP message is never mistaken for a header.
pub(crate) fn strip_ipv4_header(bytes: &[u8]) -> std::io::Result<&[u8]> {
    match bytes.first() {
        Some(&b) if b >> 4 == 4 && b & 0x0F >= 5 => {
            let header_len = usize::from(b & 0x0F) * 4;
            bytes.get(header_len..).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "truncated IPv4 header")
            })
        }
        _ => Ok(bytes),
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

/// The identifier a datagram (ping) socket uses on the wire.
pub(crate) fn dgram_identifier(sock: &Socket) -> u16 {
    if cfg!(target_os = "macos") {
        // macOS keeps the identifier the caller sets, assigns the socket no
        // port, and delivers every reply to every datagram ICMP socket. Use
        // the process ID, as macOS ping does.
        std::process::id() as u16
    } else {
        // Linux replaces the identifier with the socket's local port.
        local_port(sock).unwrap_or(0)
    }
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
    pub(crate) opts: SockOpts,
}

/// The options a socket applies on send and receive. The kernel keeps an
/// option once set, so each value is applied only when it changed.
pub(crate) struct SockOpts {
    /// The hop limit (TTL). `None` keeps the OS default.
    pub(crate) hops: Option<u32>,
    pub(crate) timeout: Option<Duration>,
    applied_hops: Option<u32>,
    /// `None` until a timeout was applied.
    applied_timeout: Option<Option<Duration>>,
}

impl SockOpts {
    fn new() -> Self {
        Self {
            hops: None,
            timeout: None,
            applied_hops: None,
            applied_timeout: None,
        }
    }

    /// Apply the hop limit if the caller set or changed it.
    pub(crate) fn apply_hops<F: Family>(&mut self, sock: &Socket) -> std::io::Result<()> {
        if let Some(hops) = self.hops {
            if self.applied_hops != Some(hops) {
                F::set_hops(sock, hops)?;
                self.applied_hops = Some(hops);
            }
        }
        Ok(())
    }

    /// Apply the read timeout if it changed.
    fn apply_timeout(&mut self, sock: &Socket) -> std::io::Result<()> {
        if self.applied_timeout != Some(self.timeout) {
            sock.set_read_timeout(self.timeout)?;
            self.applied_timeout = Some(self.timeout);
        }
        Ok(())
    }
}

impl<F: Family> Core<F> {
    fn open(ty: Type) -> std::io::Result<Self> {
        Ok(Self {
            inner: Socket::new(F::DOMAIN, ty, Some(F::PROTOCOL))?,
            bound_to: None,
            buf: Vec::with_capacity(DEFAULT_RECV_BUFFER_SIZE),
            buf_size: DEFAULT_RECV_BUFFER_SIZE,
            opts: SockOpts::new(),
        })
    }

    fn bind(&mut self, addr: F::Addr) -> std::io::Result<()> {
        self.bound_to = Some(addr);
        self.inner.bind(&to_sockaddr(addr))
    }

    fn set_read_buffer_size(&mut self, size: usize) {
        self.buf_size = size;
    }

    fn send_bytes(&mut self, dest: F::Addr, bytes: &[u8]) -> std::io::Result<()> {
        self.opts.apply_hops::<F>(&self.inner)?;
        self.inner.send_to(bytes, &to_sockaddr(dest))?;
        Ok(())
    }

    fn recv(&mut self) -> std::io::Result<(F::Packet, SockAddr)> {
        self.opts.apply_timeout(&self.inner)?;
        let received = recv_into(&self.inner, &mut self.buf, self.buf_size).map_err(|e| {
            // An expired SO_RCVTIMEO is EAGAIN (WouldBlock) on Unix. Report it
            // as TimedOut, as the async sockets do.
            if self.opts.timeout.is_some() && e.kind() == std::io::ErrorKind::WouldBlock {
                timed_out_error()
            } else {
                e
            }
        })?;
        Ok((
            decode_received::<F>(&self.buf, received.truncated)?,
            received.addr,
        ))
    }
}

/// The error returned when `rcv_from` waited longer than the socket's timeout.
pub(crate) fn timed_out_error() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::TimedOut, "rcv_from timed out")
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
    type PacketType = Icmpv4Message;

    fn set_max_hops(&mut self, hops: u32) {
        self.core.opts.hops = Some(hops);
    }

    fn bind<A: Into<Self::AddrType>>(&mut self, addr: A) -> std::io::Result<()> {
        self.core.bind(addr.into())
    }

    fn send_to(&mut self, dest: Self::AddrType, packet: Self::PacketType) -> std::io::Result<()> {
        self.core.send_bytes(dest, &packet.to_bytes())
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
/// port. This type therefore owns the identifier, reported by
/// [`Self::identifier`], and its [`Self::send`] takes only the sequence and
/// payload. Match replies against [`Self::identifier`].
///
/// On macOS every datagram ICMP socket receives every reply, so the caller
/// must filter replies.
pub struct DgramIcmpSocket4 {
    core: Core<V4>,
}

impl DgramIcmpSocket4 {
    /// Construct a new datagram socket. The kernel binds it on the first send
    /// if [`Self::bind`] was not called.
    pub fn new() -> std::io::Result<Self> {
        Ok(Self {
            core: Core::open(Type::DGRAM)?,
        })
    }

    /// Bind the socket to a local address.
    pub fn bind<A: Into<Ipv4Addr>>(&mut self, addr: A) -> std::io::Result<()> {
        self.core.bind(addr.into())
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
    /// that belong to this socket.
    ///
    /// On Linux this is the socket's local port, read from the socket on each
    /// call. The kernel assigns a unique port at [`Self::bind`] or at the
    /// first send, and the value is `0` before that.
    ///
    /// On macOS a datagram ICMP socket has no port, and the kernel keeps the
    /// identifier the sender sets. This is the low 16 bits of the process ID,
    /// as macOS `ping` uses, so two sockets in one process share it.
    pub fn identifier(&self) -> u16 {
        dgram_identifier(&self.core.inner)
    }

    /// Sets the ttl for packets sent on this socket. Until it is called, the
    /// OS default applies.
    pub fn set_max_hops(&mut self, hops: u32) {
        self.core.opts.hops = Some(hops);
    }

    /// Sets the timeout on the socket for `rcv_from`. A value of None blocks.
    /// When the timeout expires, `rcv_from` returns an error of kind
    /// `TimedOut`.
    pub fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.core.opts.timeout = timeout;
    }

    /// Send an echo request to `dest`. The identifier is supplied by the socket,
    /// so the caller provides only the sequence number and payload.
    pub fn send(&mut self, dest: Ipv4Addr, sequence: u16, payload: Vec<u8>) -> std::io::Result<()> {
        let packet = Icmpv4Message::echo_request(self.identifier(), sequence, payload);
        self.core.send_bytes(dest, &packet.to_bytes())
    }

    /// Receive a packet. Replies are not filtered; compare against
    /// [`Self::identifier`] to select those belonging to this socket.
    pub fn rcv_from(&mut self) -> std::io::Result<(Icmpv4Message, SockAddr)> {
        self.core.recv()
    }

    #[cfg(feature = "smol")]
    pub fn into_async(self) -> std::io::Result<crate::smol::AsyncDgramIcmpV4Socket> {
        crate::smol::AsyncDgramIcmpV4Socket::new(self.core)
    }
}

/// A raw ICMPv6 socket. Requires elevated privileges.
///
/// The kernel computes the checksum of every ICMPv6 packet sent on this
/// socket and verifies it on every packet received (RFC 3542 section 3.1),
/// so the socket does not need to be bound to send.
pub struct IcmpSocket6 {
    core: Core<V6>,
}

impl IcmpSocket6 {
    /// Construct a new raw socket. Bind it with `bind` to choose the local
    /// address; otherwise the kernel chooses one for each destination.
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
    type PacketType = Icmpv6Message;

    fn set_max_hops(&mut self, hops: u32) {
        self.core.opts.hops = Some(hops);
    }

    fn bind<A: Into<Self::AddrType>>(&mut self, addr: A) -> std::io::Result<()> {
        self.core.bind(addr.into())
    }

    /// Sends the packet to the given destination. The kernel fills in the
    /// checksum, so any checksum set on `packet` is ignored.
    fn send_to(&mut self, dest: Self::AddrType, packet: Self::PacketType) -> std::io::Result<()> {
        self.core.send_bytes(dest, &packet.to_bytes_unchecksummed())
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
