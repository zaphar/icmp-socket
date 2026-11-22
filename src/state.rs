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
//! The I/O-free part of every socket: its state, and the send and receive
//! machines that the blocking and async sockets drive.
use std::convert::Infallible;
use std::io;
use std::marker::PhantomData;
use std::net::Ipv4Addr;
use std::os::fd::BorrowedFd;

use socket2::{Domain, Protocol, SockAddr, SockRef};

use crate::addr::ScopedIpv6Addr;
use crate::error::{Ipv4RecvError, ParseError, RecvError};
use crate::machine::{Interest, Machine, Next, Progress};
use crate::sys::{self, Peer, Received};
use crate::{Icmpv4Message, Icmpv6Message};

/// The default maximum message size: a reply on a typical Ethernet MTU.
pub(crate) const DEFAULT_MAX_MESSAGE_SIZE: usize = 2048;

/// Options for one send: fields of the IP header of the packet that carries
/// the message. They apply to that send only; a plain send uses the system
/// defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SendOptions {
    hop_limit: Option<u8>,
}

impl SendOptions {
    /// All system defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// The hop limit (the TTL on IPv4).
    pub fn hop_limit(mut self, hops: u8) -> Self {
        self.hop_limit = Some(hops);
        self
    }
}

/// Facts about a received packet from its IP header and the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecvInfo<A> {
    source: A,
    hop_limit: Option<u8>,
    local_addr: Option<A>,
    interface_index: Option<u32>,
}

impl<A: Copy> RecvInfo<A> {
    /// The address the packet came from.
    pub fn source(&self) -> A {
        self.source
    }

    /// The packet's hop limit (TTL) on arrival.
    pub fn hop_limit(&self) -> Option<u8> {
        self.hop_limit
    }

    /// The local address the packet was sent to.
    pub fn local_addr(&self) -> Option<A> {
        self.local_addr
    }

    /// The index of the interface the packet arrived on.
    pub fn interface_index(&self) -> Option<u32> {
        self.interface_index
    }
}

/// What differs between ICMPv4 and ICMPv6 for the state and machines.
pub(crate) trait Family: Sized + 'static {
    const DOMAIN: Domain;
    const PROTOCOL: Protocol;
    type Addr: Copy + std::fmt::Debug;
    type Message;
    type Proto;
    /// Room in the read buffer for an IP header the system may deliver in
    /// front of the message.
    const HEADER_ROOM: usize;

    fn sockaddr(addr: Self::Addr) -> SockAddr;
    fn addr(peer: Peer) -> Option<Self::Addr>;
    fn enable_info(fd: BorrowedFd<'_>, error_queue: bool) -> io::Result<()>;
    /// The hop-limit value that restores the system default.
    fn default_hops(fd: BorrowedFd<'_>) -> io::Result<libc::c_int>;
    fn set_hops(fd: BorrowedFd<'_>, hops: libc::c_int) -> io::Result<()>;
    /// Remove any IP header in front of the message and fill in what the
    /// header says. Returns the offset of the ICMP message.
    fn frame(bytes: &[u8], info: &mut Received) -> Result<usize, Self::Proto>;
    /// Check what the kernel does not check (the ICMPv4 checksum).
    fn verify(icmp: &[u8]) -> Result<(), Self::Proto>;
    fn parse(icmp: &[u8]) -> Result<Self::Message, ParseError>;
    /// Serialize for a socket (ICMPv6: the kernel fills the checksum in).
    fn encode(msg: &Self::Message, out: &mut Vec<u8>);
    fn echo_request(identifier: u16, sequence: u16, payload: &[u8]) -> Self::Message;
    fn local(info: &Received) -> Option<Self::Addr>;
}

pub(crate) enum V4 {}

impl Family for V4 {
    const DOMAIN: Domain = Domain::IPV4;
    const PROTOCOL: Protocol = Protocol::ICMPV4;
    type Addr = Ipv4Addr;
    type Message = Icmpv4Message;
    type Proto = Ipv4RecvError;
    /// The largest IPv4 header (IHL 15).
    const HEADER_ROOM: usize = 60;

    fn sockaddr(addr: Ipv4Addr) -> SockAddr {
        sys::sockaddr_v4(addr)
    }

    fn addr(peer: Peer) -> Option<Ipv4Addr> {
        match peer {
            Peer::V4(a) => Some(a),
            Peer::V6(_) => None,
        }
    }

    fn enable_info(fd: BorrowedFd<'_>, error_queue: bool) -> io::Result<()> {
        sys::enable_v4_info(fd, error_queue)
    }

    fn default_hops(fd: BorrowedFd<'_>) -> io::Result<libc::c_int> {
        sys::hop_limit_v4(fd)
    }

    fn set_hops(fd: BorrowedFd<'_>, hops: libc::c_int) -> io::Result<()> {
        sys::set_hop_limit_v4(fd, hops)
    }

    /// Raw sockets always deliver the IPv4 header, Linux datagram sockets
    /// never do, and macOS datagram sockets do. A valid IPv4 header starts
    /// with version 4 and an IHL of at least 5 (`0x45..=0x4F`); no assigned
    /// ICMP type is in that range.
    fn frame(bytes: &[u8], info: &mut Received) -> Result<usize, Ipv4RecvError> {
        match bytes.first() {
            Some(&b) if b >> 4 == 4 && b & 0x0F >= 5 => {
                let header_len = usize::from(b & 0x0F) * 4;
                if bytes.len() < header_len {
                    return Err(Ipv4RecvError::InvalidIpHeader);
                }
                info.hop_limit = Some(bytes[8]);
                info.local_v4 = Some(Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]));
                Ok(header_len)
            }
            _ => Ok(0),
        }
    }

    fn verify(icmp: &[u8]) -> Result<(), Ipv4RecvError> {
        // Shorter messages fail to parse; report that instead.
        if icmp.len() >= 4 && !Icmpv4Message::verify_checksum(icmp) {
            return Err(Ipv4RecvError::BadChecksum);
        }
        Ok(())
    }

    fn parse(icmp: &[u8]) -> Result<Icmpv4Message, ParseError> {
        Icmpv4Message::parse(icmp)
    }

    fn encode(msg: &Icmpv4Message, out: &mut Vec<u8>) {
        msg.write_to(out)
    }

    fn echo_request(identifier: u16, sequence: u16, payload: &[u8]) -> Icmpv4Message {
        Icmpv4Message::echo_request(identifier, sequence, payload.to_vec())
    }

    fn local(info: &Received) -> Option<Ipv4Addr> {
        info.local_v4
    }
}

pub(crate) enum V6 {}

impl Family for V6 {
    const DOMAIN: Domain = Domain::IPV6;
    const PROTOCOL: Protocol = Protocol::ICMPV6;
    type Addr = ScopedIpv6Addr;
    type Message = Icmpv6Message;
    type Proto = Infallible;
    const HEADER_ROOM: usize = 0;

    fn sockaddr(addr: ScopedIpv6Addr) -> SockAddr {
        sys::sockaddr_v6(addr)
    }

    fn addr(peer: Peer) -> Option<ScopedIpv6Addr> {
        match peer {
            Peer::V6(a) => Some(a),
            Peer::V4(_) => None,
        }
    }

    fn enable_info(fd: BorrowedFd<'_>, error_queue: bool) -> io::Result<()> {
        sys::enable_v6_info(fd, error_queue)
    }

    fn default_hops(_fd: BorrowedFd<'_>) -> io::Result<libc::c_int> {
        // RFC 3493: -1 selects the route's default.
        Ok(-1)
    }

    fn set_hops(fd: BorrowedFd<'_>, hops: libc::c_int) -> io::Result<()> {
        sys::set_hop_limit_v6(fd, hops)
    }

    /// IPv6 sockets never deliver the IPv6 header.
    fn frame(_bytes: &[u8], _info: &mut Received) -> Result<usize, Infallible> {
        Ok(0)
    }

    /// The kernel verifies every ICMPv6 checksum (RFC 3542 section 3.1).
    fn verify(_icmp: &[u8]) -> Result<(), Infallible> {
        Ok(())
    }

    fn parse(icmp: &[u8]) -> Result<Icmpv6Message, ParseError> {
        Icmpv6Message::parse(icmp)
    }

    fn encode(msg: &Icmpv6Message, out: &mut Vec<u8>) {
        msg.write_to_unchecksummed(out)
    }

    fn echo_request(identifier: u16, sequence: u16, payload: &[u8]) -> Icmpv6Message {
        Icmpv6Message::echo_request(identifier, sequence, payload.to_vec())
    }

    fn local(info: &Received) -> Option<ScopedIpv6Addr> {
        let addr = info.local_v6?;
        let scoped = addr.is_unicast_link_local() || addr.is_multicast();
        let scope_id = if scoped {
            info.interface_index.unwrap_or(0)
        } else {
            0
        };
        Some(ScopedIpv6Addr::new(addr, scope_id))
    }
}

/// The identifier a datagram (ping) socket uses on the wire.
pub(crate) fn dgram_identifier(fd: BorrowedFd<'_>) -> u16 {
    if cfg!(target_os = "macos") {
        // macOS keeps the identifier the sender sets, assigns the socket no
        // port, and delivers every reply to every datagram ICMP socket. Use
        // the process ID, as macOS ping does.
        std::process::id() as u16
    } else {
        // Linux replaces the identifier with the socket's local port.
        SockRef::from(&fd)
            .local_addr()
            .ok()
            .and_then(|a| a.as_socket())
            .map(|a| a.port())
            .unwrap_or(0)
    }
}

/// The state every socket kind shares.
pub(crate) struct Core<F: Family> {
    pub(crate) buf: Vec<u8>,
    pub(crate) max: usize,
    send_buf: Vec<u8>,
    default_hops: libc::c_int,
    /// The hop limit last set on the socket; `None` is the system default.
    applied_hops: Option<u8>,
    family: PhantomData<F>,
}

impl<F: Family> Core<F> {
    /// Set up a newly opened socket.
    pub(crate) fn new(fd: BorrowedFd<'_>, _raw: bool) -> io::Result<Self> {
        F::enable_info(fd, false)?;
        Ok(Self {
            buf: Vec::with_capacity(DEFAULT_MAX_MESSAGE_SIZE),
            max: DEFAULT_MAX_MESSAGE_SIZE,
            send_buf: Vec::new(),
            default_hops: F::default_hops(fd)?,
            applied_hops: None,
            family: PhantomData,
        })
    }

    pub(crate) fn set_max_message_size(&mut self, size: usize) {
        self.max = size;
    }

    pub(crate) fn send<'a>(
        &'a mut self,
        dest: F::Addr,
        payload: Payload<'a, F>,
        opts: &SendOptions,
    ) -> SendMachine<'a, F> {
        SendMachine {
            dest: F::sockaddr(dest),
            hops: opts.hop_limit,
            core: self,
            payload,
            step: SendStep::Hops,
            result: None,
        }
    }

    pub(crate) fn recv<M: RecvMode<F>>(&mut self) -> RecvMachine<'_, F, M> {
        RecvMachine {
            core: Some(self),
            outcome: None,
            mode: PhantomData,
        }
    }
}

/// What a send puts on the wire.
pub(crate) enum Payload<'a, F: Family> {
    Message(&'a F::Message),
    Raw(&'a [u8]),
    Echo { sequence: u16, payload: &'a [u8] },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendStep {
    Hops,
    Send,
}

/// Sends one message: sets the hop limit if this send needs a different one
/// than the last, then sends.
pub(crate) struct SendMachine<'a, F: Family> {
    core: &'a mut Core<F>,
    dest: SockAddr,
    payload: Payload<'a, F>,
    hops: Option<u8>,
    step: SendStep,
    result: Option<io::Result<()>>,
}

impl<F: Family> Machine for SendMachine<'_, F> {
    type Output = io::Result<()>;

    fn next(&mut self) -> Next<io::Result<()>> {
        if let Some(result) = self.result.take() {
            return Next::Done(result);
        }
        if self.step == SendStep::Hops && self.core.applied_hops == self.hops {
            self.step = SendStep::Send;
        }
        match self.step {
            SendStep::Hops => Next::Io(Interest::None),
            SendStep::Send => Next::Io(Interest::Write),
        }
    }

    fn perform(&mut self, fd: BorrowedFd<'_>) -> Progress {
        match self.step {
            SendStep::Hops => {
                let value = self.hops.map_or(self.core.default_hops, libc::c_int::from);
                match F::set_hops(fd, value) {
                    Ok(()) => {
                        self.core.applied_hops = self.hops;
                        self.step = SendStep::Send;
                    }
                    Err(e) => self.result = Some(Err(e)),
                }
                Progress::Continue
            }
            SendStep::Send => {
                let bytes: &[u8] = match &self.payload {
                    Payload::Raw(bytes) => bytes,
                    Payload::Message(msg) => {
                        self.core.send_buf.clear();
                        F::encode(msg, &mut self.core.send_buf);
                        &self.core.send_buf
                    }
                    Payload::Echo { sequence, payload } => {
                        let msg = F::echo_request(dgram_identifier(fd), *sequence, payload);
                        self.core.send_buf.clear();
                        F::encode(&msg, &mut self.core.send_buf);
                        &self.core.send_buf
                    }
                };
                match SockRef::from(&fd).send_to(bytes, &self.dest) {
                    Ok(_) => {
                        self.result = Some(Ok(()));
                        Progress::Continue
                    }
                    Err(e) if sys::would_block(&e) => Progress::WouldBlock,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => Progress::Continue,
                    Err(e) => {
                        self.result = Some(Err(e));
                        Progress::Continue
                    }
                }
            }
        }
    }

    fn fail(&mut self, err: io::Error) {
        self.result = Some(Err(err));
    }
}

/// How a receive hands back its message.
pub(crate) trait RecvMode<F: Family> {
    type Output<'a>;
    const PARSE: bool;
    fn output<'a>(
        core: &'a Core<F>,
        outcome: Result<(usize, RecvInfo<F::Addr>), RecvError<F::Proto>>,
    ) -> Self::Output<'a>;
}

/// Parse the message.
pub(crate) struct Parsed;
/// Parse the message and keep only its source.
pub(crate) struct ParsedFrom;
/// Hand back the ICMP bytes.
pub(crate) struct Raw;

impl<F: Family> RecvMode<F> for Parsed {
    type Output<'a> = Result<(F::Message, RecvInfo<F::Addr>), RecvError<F::Proto>>;
    const PARSE: bool = true;
    fn output<'a>(
        core: &'a Core<F>,
        outcome: Result<(usize, RecvInfo<F::Addr>), RecvError<F::Proto>>,
    ) -> Self::Output<'a> {
        let (start, info) = outcome?;
        Ok((F::parse(&core.buf[start..])?, info))
    }
}

impl<F: Family> RecvMode<F> for ParsedFrom {
    type Output<'a> = Result<(F::Message, F::Addr), RecvError<F::Proto>>;
    const PARSE: bool = true;
    fn output<'a>(
        core: &'a Core<F>,
        outcome: Result<(usize, RecvInfo<F::Addr>), RecvError<F::Proto>>,
    ) -> Self::Output<'a> {
        let (msg, info) = <Parsed as RecvMode<F>>::output(core, outcome)?;
        Ok((msg, info.source))
    }
}

impl<F: Family> RecvMode<F> for Raw {
    type Output<'a> = Result<(&'a [u8], RecvInfo<F::Addr>), RecvError<F::Proto>>;
    const PARSE: bool = false;
    fn output<'a>(
        core: &'a Core<F>,
        outcome: Result<(usize, RecvInfo<F::Addr>), RecvError<F::Proto>>,
    ) -> Self::Output<'a> {
        let (start, info) = outcome?;
        Ok((&core.buf[start..], info))
    }
}

/// Receives one message: reads it, removes any IP header, checks it and
/// fills in [`RecvInfo`].
pub(crate) struct RecvMachine<'a, F: Family, M: RecvMode<F>> {
    core: Option<&'a mut Core<F>>,
    outcome: Option<Result<(usize, RecvInfo<F::Addr>), RecvError<F::Proto>>>,
    mode: PhantomData<M>,
}

impl<F: Family, M: RecvMode<F>> RecvMachine<'_, F, M> {
    fn core(&mut self) -> &mut Core<F> {
        self.core
            .as_deref_mut()
            .expect("a finished machine was used again")
    }

    /// Process one received message.
    fn process(&mut self, mut received: Received) {
        let core = self.core();
        if received.truncated {
            let buf_size = core.max;
            self.outcome = Some(Err(RecvError::Truncated { buf_size }));
            return;
        }
        let Some(source) = received.from.and_then(F::addr) else {
            self.outcome = Some(Err(RecvError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "received a packet without a source address of this family",
            ))));
            return;
        };
        let start = match F::frame(&core.buf, &mut received) {
            Ok(start) => start,
            Err(e) => {
                self.outcome = Some(Err(RecvError::Protocol(e)));
                return;
            }
        };
        // The maximum counts the ICMP message only, on every system.
        if core.buf.len() - start > core.max {
            let buf_size = core.max;
            self.outcome = Some(Err(RecvError::Truncated { buf_size }));
            return;
        }
        if M::PARSE {
            if let Err(e) = F::verify(&core.buf[start..]) {
                self.outcome = Some(Err(RecvError::Protocol(e)));
                return;
            }
        }
        let info = RecvInfo {
            source,
            hop_limit: received.hop_limit,
            local_addr: F::local(&received),
            interface_index: received.interface_index,
        };
        self.outcome = Some(Ok((start, info)));
    }
}

impl<'a, F: Family, M: RecvMode<F>> Machine for RecvMachine<'a, F, M> {
    type Output = M::Output<'a>;

    fn next(&mut self) -> Next<M::Output<'a>> {
        match self.outcome.take() {
            Some(outcome) => {
                let core: &'a Core<F> =
                    self.core.take().expect("a finished machine was used again");
                Next::Done(M::output(core, outcome))
            }
            None => Next::Io(Interest::Read),
        }
    }

    fn perform(&mut self, fd: BorrowedFd<'_>) -> Progress {
        let core = self.core();
        let read_size = core.max + F::HEADER_ROOM;
        match sys::recvmsg(fd, &mut core.buf, read_size, false) {
            Ok(received) => {
                self.process(received);
                Progress::Continue
            }
            Err(e) if sys::would_block(&e) => Progress::WouldBlock,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => Progress::Continue,
            Err(e) => {
                self.outcome = Some(Err(RecvError::Io(e)));
                Progress::Continue
            }
        }
    }

    fn fail(&mut self, err: io::Error) {
        self.outcome = Some(Err(if err.kind() == io::ErrorKind::TimedOut {
            RecvError::Timeout
        } else {
            RecvError::Io(err)
        }));
    }
}
