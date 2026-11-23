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
//! System calls and socket options the sockets need, with the OS
//! differences in one place. Everything here is private; the `unsafe`
//! blocks stay behind safe functions.
use std::io;
use std::mem::{self, MaybeUninit};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, BorrowedFd};

use crate::addr::ScopedIpv6Addr;

/// One message read with `recvmsg`.
#[derive(Debug, Default)]
pub(crate) struct Received {
    pub(crate) truncated: bool,
    pub(crate) from: Option<Peer>,
    pub(crate) hop_limit: Option<u8>,
    pub(crate) local_v4: Option<Ipv4Addr>,
    pub(crate) local_v6: Option<Ipv6Addr>,
    pub(crate) interface_index: Option<u32>,
    #[cfg(target_os = "linux")]
    pub(crate) extended_error: Option<ExtendedError>,
}

/// The source address of a received message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Peer {
    V4(Ipv4Addr),
    V6(ScopedIpv6Addr),
}

/// A Linux `sock_extended_err` from the error queue (ADR 0012).
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExtendedError {
    pub(crate) errno: u32,
    pub(crate) origin: u8,
    pub(crate) typ: u8,
    pub(crate) code: u8,
    pub(crate) info: u32,
    pub(crate) offender: Option<Peer>,
}

/// `struct sock_extended_err` (linux/errqueue.h); not in the libc crate.
#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
struct SockExtendedErr {
    ee_errno: u32,
    ee_origin: u8,
    ee_type: u8,
    ee_code: u8,
    #[allow(dead_code)]
    ee_pad: u8,
    ee_info: u32,
    #[allow(dead_code)]
    ee_data: u32,
}

#[cfg(target_os = "linux")]
pub(crate) const ORIGIN_LOCAL: u8 = libc::SO_EE_ORIGIN_LOCAL;
#[cfg(target_os = "linux")]
pub(crate) const ORIGIN_ICMP: u8 = libc::SO_EE_ORIGIN_ICMP;
#[cfg(target_os = "linux")]
pub(crate) const ORIGIN_ICMP6: u8 = libc::SO_EE_ORIGIN_ICMP6;

fn cvt(ret: libc::c_int) -> io::Result<libc::c_int> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// Set an `int` socket option.
pub(crate) fn set_int(
    fd: BorrowedFd<'_>,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    set_raw(fd, level, name, &value)
}

/// Read an `int` socket option.
pub(crate) fn get_int(
    fd: BorrowedFd<'_>,
    level: libc::c_int,
    name: libc::c_int,
) -> io::Result<libc::c_int> {
    let mut value: libc::c_int = 0;
    let mut len = mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `value` and `len` describe a valid c_int buffer.
    cvt(unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            level,
            name,
            (&mut value as *mut libc::c_int).cast(),
            &mut len,
        )
    })?;
    Ok(value)
}

/// Set a socket option whose value is a plain C struct or array `T`.
fn set_raw<T: Copy>(
    fd: BorrowedFd<'_>,
    level: libc::c_int,
    name: libc::c_int,
    value: &T,
) -> io::Result<()> {
    // SAFETY: `value` points to `size_of::<T>()` readable bytes.
    cvt(unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            name,
            (value as *const T).cast(),
            mem::size_of::<T>() as libc::socklen_t,
        )
    })
    .map(|_| ())
}

/// Turn on the ancillary data that [`RecvInfo`](crate::RecvInfo) and the
/// error queue need, for a v4 socket.
pub(crate) fn enable_v4_info(fd: BorrowedFd<'_>, error_queue: bool) -> io::Result<()> {
    set_int(fd, libc::IPPROTO_IP, libc::IP_RECVTTL, 1)?;
    // The arrival address and interface. macOS does not accept
    // IP_RECVPKTINFO on ICMP sockets, so it reports them separately.
    #[cfg(target_os = "linux")]
    set_int(fd, libc::IPPROTO_IP, libc::IP_PKTINFO, 1)?;
    #[cfg(not(target_os = "linux"))]
    {
        set_int(fd, libc::IPPROTO_IP, libc::IP_RECVDSTADDR, 1)?;
        set_int(fd, libc::IPPROTO_IP, libc::IP_RECVIF, 1)?;
    }
    #[cfg(target_os = "linux")]
    if error_queue {
        set_int(fd, libc::IPPROTO_IP, libc::IP_RECVERR, 1)?;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = error_queue;
    Ok(())
}

/// Turn on the ancillary data for a v6 socket.
pub(crate) fn enable_v6_info(fd: BorrowedFd<'_>, error_queue: bool) -> io::Result<()> {
    set_int(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVHOPLIMIT, 1)?;
    set_int(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, 1)?;
    #[cfg(target_os = "linux")]
    if error_queue {
        set_int(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVERR, 1)?;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = error_queue;
    Ok(())
}

/// Set the unicast hop limit. `None` restores the system default.
pub(crate) fn set_hop_limit_v4(fd: BorrowedFd<'_>, hops: libc::c_int) -> io::Result<()> {
    set_int(fd, libc::IPPROTO_IP, libc::IP_TTL, hops)
}

pub(crate) fn hop_limit_v4(fd: BorrowedFd<'_>) -> io::Result<libc::c_int> {
    get_int(fd, libc::IPPROTO_IP, libc::IP_TTL)
}

/// Set the IPv6 unicast hop limit; -1 means the route's default (RFC 3493).
pub(crate) fn set_hop_limit_v6(fd: BorrowedFd<'_>, hops: libc::c_int) -> io::Result<()> {
    set_int(fd, libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS, hops)
}

/// The Linux raw-socket option `ICMP_FILTER` (linux/icmp.h): a 32-bit mask
/// of ICMPv4 types 0..32 to block. Not in the libc crate.
#[cfg(target_os = "linux")]
pub(crate) fn set_icmp_filter_v4(fd: BorrowedFd<'_>, blocked: u32) -> io::Result<()> {
    const SOL_RAW: libc::c_int = 255;
    const ICMP_FILTER: libc::c_int = 1;
    set_raw(fd, SOL_RAW, ICMP_FILTER, &blocked)
}

/// Set `ICMP6_FILTER` (RFC 3542). `blocked` has one bit per type, set to
/// block. Not in the libc crate; the option number and the bit meaning
/// differ: on Linux a set bit blocks, in the KAME stack (macOS) a set bit
/// passes.
pub(crate) fn set_icmp6_filter(fd: BorrowedFd<'_>, blocked: [u32; 8]) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        const ICMP6_FILTER: libc::c_int = 1;
        set_raw(fd, libc::IPPROTO_ICMPV6, ICMP6_FILTER, &blocked)
    }
    #[cfg(not(target_os = "linux"))]
    {
        const ICMP6_FILTER: libc::c_int = 18;
        let passed = blocked.map(|w| !w);
        set_raw(fd, libc::IPPROTO_ICMPV6, ICMP6_FILTER, &passed)
    }
}

/// Read one message into the spare capacity of `buf` (at most `max`
/// bytes) with `recvmsg`. On return `buf` holds the bytes received.
/// `error_queue` reads the Linux error queue instead (non-blocking).
pub(crate) fn recvmsg(
    fd: BorrowedFd<'_>,
    buf: &mut Vec<u8>,
    max: usize,
    error_queue: bool,
) -> io::Result<Received> {
    buf.clear();
    buf.reserve(max);
    let mut control = [MaybeUninit::<u8>::uninit(); 256];
    // SAFETY: an all-zero sockaddr_storage is a valid value.
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: buf.spare_capacity_mut().as_mut_ptr().cast(),
        iov_len: max,
    };
    // SAFETY: an all-zero msghdr is a valid value; the fields are set below.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_name = (&mut storage as *mut libc::sockaddr_storage).cast();
    msg.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control.len() as _;
    #[allow(unused_mut)]
    let mut flags = 0;
    #[cfg(target_os = "linux")]
    if error_queue {
        flags |= libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = error_queue;
    // SAFETY: every pointer in `msg` points to a live buffer of the stated
    // length for the duration of the call.
    let n = unsafe { libc::recvmsg(fd.as_raw_fd(), &mut msg, flags) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let n = n as usize;
    // SAFETY: recvmsg initialized the first `n` bytes of the buffer.
    unsafe { buf.set_len(n) };
    let mut received = Received {
        truncated: msg.msg_flags & libc::MSG_TRUNC != 0,
        // SAFETY: recvmsg wrote a sockaddr of `msg_namelen` bytes.
        from: unsafe { peer(&storage, msg.msg_namelen) },
        ..Received::default()
    };
    // SAFETY: recvmsg wrote `msg_controllen` bytes of control messages, and
    // `msg` still points to that buffer.
    unsafe { read_control(&msg, &mut received) };
    Ok(received)
}

/// Decode a sockaddr written by the kernel.
///
/// # Safety
/// `storage` holds a sockaddr of `len` bytes written by the kernel.
unsafe fn peer(storage: &libc::sockaddr_storage, len: libc::socklen_t) -> Option<Peer> {
    let len = len as usize;
    match storage.ss_family as libc::c_int {
        libc::AF_INET if len >= mem::size_of::<libc::sockaddr_in>() => {
            // SAFETY: the family and length say it is a sockaddr_in.
            let sin = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            Some(Peer::V4(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr))))
        }
        libc::AF_INET6 if len >= mem::size_of::<libc::sockaddr_in6>() => {
            // SAFETY: the family and length say it is a sockaddr_in6.
            let sin6 = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            Some(Peer::V6(ScopedIpv6Addr::new(
                Ipv6Addr::from(sin6.sin6_addr.s6_addr),
                sin6.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

/// Copy a `T` out of control message data, which need not be aligned.
fn read_unaligned<T: Copy>(data: &[u8]) -> Option<T> {
    if data.len() < mem::size_of::<T>() {
        return None;
    }
    // SAFETY: `data` holds at least size_of::<T>() bytes, and T is a plain C
    // type for which any bit pattern from the kernel is valid.
    Some(unsafe { std::ptr::read_unaligned(data.as_ptr().cast::<T>()) })
}

/// Read the control messages after a `recvmsg`.
///
/// # Safety
/// `msg` was just filled in by a successful `recvmsg`, and its control
/// buffer is still alive.
unsafe fn read_control(msg: &libc::msghdr, out: &mut Received) {
    // SAFETY: per the function's contract, the CMSG_* walk stays inside the
    // control buffer the kernel filled.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(msg);
        while !cmsg.is_null() {
            let header = &*cmsg;
            let data_ptr = libc::CMSG_DATA(cmsg);
            let header_len = data_ptr as usize - cmsg as usize;
            let data_len = (header.cmsg_len as usize).saturating_sub(header_len);
            let data = std::slice::from_raw_parts(data_ptr, data_len);
            read_one(header.cmsg_level, header.cmsg_type, data, out);
            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
    }
}

fn read_one(level: libc::c_int, typ: libc::c_int, data: &[u8], out: &mut Received) {
    match (level, typ) {
        (libc::IPPROTO_IP, libc::IP_TTL) => {
            out.hop_limit = read_unaligned::<libc::c_int>(data).map(|v| v as u8);
        }
        #[cfg(not(target_os = "linux"))]
        (libc::IPPROTO_IP, libc::IP_RECVTTL) => {
            out.hop_limit = data.first().copied();
        }
        #[cfg(target_os = "linux")]
        (libc::IPPROTO_IP, libc::IP_PKTINFO) => {
            if let Some(info) = read_unaligned::<libc::in_pktinfo>(data) {
                out.interface_index = Some(info.ipi_ifindex as u32);
                out.local_v4 = Some(Ipv4Addr::from(u32::from_be(info.ipi_addr.s_addr)));
            }
        }
        #[cfg(not(target_os = "linux"))]
        (libc::IPPROTO_IP, libc::IP_RECVDSTADDR) => {
            if let Some(addr) = read_unaligned::<libc::in_addr>(data) {
                out.local_v4 = Some(Ipv4Addr::from(u32::from_be(addr.s_addr)));
            }
        }
        #[cfg(not(target_os = "linux"))]
        (libc::IPPROTO_IP, libc::IP_RECVIF) => {
            if let Some(dl) = read_unaligned::<libc::sockaddr_dl>(data) {
                out.interface_index = Some(u32::from(dl.sdl_index));
            }
        }
        (libc::IPPROTO_IPV6, libc::IPV6_HOPLIMIT) => {
            out.hop_limit = read_unaligned::<libc::c_int>(data).map(|v| v as u8);
        }
        (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => {
            if let Some(info) = read_unaligned::<libc::in6_pktinfo>(data) {
                out.interface_index = Some(info.ipi6_ifindex);
                out.local_v6 = Some(Ipv6Addr::from(info.ipi6_addr.s6_addr));
            }
        }
        #[cfg(target_os = "linux")]
        (libc::IPPROTO_IP, libc::IP_RECVERR) | (libc::IPPROTO_IPV6, libc::IPV6_RECVERR) => {
            read_extended_error(data, out);
        }
        _ => {}
    }
}

#[cfg(target_os = "linux")]
fn read_extended_error(data: &[u8], out: &mut Received) {
    let Some(ee) = read_unaligned::<SockExtendedErr>(data) else {
        return;
    };
    // The offending address follows the struct (SO_EE_OFFENDER). The kernel
    // writes as many bytes as the address needs, or zeroes (AF_UNSPEC) when
    // there is no offender.
    let rest = &data[mem::size_of::<SockExtendedErr>()..];
    // SAFETY: an all-zero sockaddr_storage is a valid value.
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let n = rest.len().min(mem::size_of::<libc::sockaddr_storage>());
    // SAFETY: copying `n` bytes into a sockaddr_storage of at least that
    // size.
    unsafe {
        std::ptr::copy_nonoverlapping(
            rest.as_ptr(),
            (&mut storage as *mut libc::sockaddr_storage).cast::<u8>(),
            n,
        )
    };
    // SAFETY: `storage` holds the kernel's sockaddr of `n` bytes.
    let offender = unsafe { peer(&storage, n as libc::socklen_t) };
    out.extended_error = Some(ExtendedError {
        errno: ee.ee_errno,
        origin: ee.ee_origin,
        typ: ee.ee_type,
        code: ee.ee_code,
        info: ee.ee_info,
        offender,
    });
}

/// The socket address for sending to `addr`.
pub(crate) fn sockaddr_v4(addr: Ipv4Addr) -> socket2::SockAddr {
    SocketAddrV4::new(addr, 0).into()
}

pub(crate) fn sockaddr_v6(addr: ScopedIpv6Addr) -> socket2::SockAddr {
    SocketAddrV6::from(addr).into()
}

/// Whether an error is the kernel's "not ready" for a non-blocking call.
pub(crate) fn would_block(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::WouldBlock
}

/// Wait with `poll` until `fd` is ready for `interest`, or `timeout` passes.
/// Returns `false` on timeout. An error condition on the socket also counts
/// as ready, so the next call reports it.
pub(crate) fn poll(
    fd: BorrowedFd<'_>,
    interest: crate::machine::Interest,
    timeout: Option<std::time::Duration>,
) -> io::Result<bool> {
    use crate::machine::Interest;
    let events = match interest {
        Interest::Read => libc::POLLIN,
        Interest::Write => libc::POLLOUT,
        Interest::None => 0,
    };
    let ms: libc::c_int = match timeout {
        None => -1,
        // Round up, so a short remaining time does not become a busy loop.
        Some(t) => t
            .as_nanos()
            .div_ceil(1_000_000)
            .min(libc::c_int::MAX as u128) as libc::c_int,
    };
    let mut pfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events,
        revents: 0,
    };
    // SAFETY: `pfd` is one valid pollfd.
    let n = cvt(unsafe { libc::poll(&mut pfd, 1, ms) })?;
    Ok(n > 0)
}
