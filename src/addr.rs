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
//! IPv6 addresses with a scope ID.
use std::ffi::{CStr, CString};
use std::fmt;
use std::io;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::str::FromStr;

/// An IPv6 address and the scope ID (interface index) that says which link
/// it belongs to.
///
/// Link-local addresses (`fe80::/10`) and link-local multicast (e.g.
/// `ff02::1`) are unique only on one link, so they need a scope ID. Global
/// addresses use scope 0.
///
/// ```
/// use icmp_socket::ScopedIpv6Addr;
///
/// let a: ScopedIpv6Addr = "fe80::1%3".parse().unwrap();
/// assert_eq!(a.scope_id, 3);
/// let b = ScopedIpv6Addr::from(std::net::Ipv6Addr::LOCALHOST);
/// assert_eq!(b.scope_id, 0);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScopedIpv6Addr {
    pub addr: Ipv6Addr,
    /// The interface index; 0 means no scope.
    pub scope_id: u32,
}

impl ScopedIpv6Addr {
    pub fn new(addr: Ipv6Addr, scope_id: u32) -> Self {
        Self { addr, scope_id }
    }

    /// The address scoped to the interface named `name` (e.g. `"en0"`).
    /// The index is looked up now; it is stale if the interface is later
    /// re-created with a new index.
    pub fn on_interface(addr: Ipv6Addr, name: &str) -> io::Result<Self> {
        Ok(Self {
            addr,
            scope_id: interface_index(name)?,
        })
    }

    /// The name of the scope's interface, or `None` for scope 0.
    pub fn interface_name(&self) -> io::Result<Option<String>> {
        if self.scope_id == 0 {
            return Ok(None);
        }
        let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
        // SAFETY: `buf` has the IF_NAMESIZE bytes if_indextoname may write.
        let name = unsafe { libc::if_indextoname(self.scope_id, buf.as_mut_ptr()) };
        if name.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: on success if_indextoname wrote a NUL-terminated name into
        // `buf`.
        let name = unsafe { CStr::from_ptr(buf.as_ptr()) };
        Ok(Some(name.to_string_lossy().into_owned()))
    }
}

/// The index of the interface named `name`.
fn interface_index(name: &str) -> io::Result<u32> {
    let c_name = CString::new(name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name contains a NUL byte",
        )
    })?;
    // SAFETY: `c_name` is a valid NUL-terminated string for the call.
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if index == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no interface named {:?}", name),
        ));
    }
    Ok(index)
}

impl From<Ipv6Addr> for ScopedIpv6Addr {
    /// Scope 0.
    fn from(addr: Ipv6Addr) -> Self {
        Self { addr, scope_id: 0 }
    }
}

impl From<SocketAddrV6> for ScopedIpv6Addr {
    /// Keeps the scope ID; drops the port and flow info, which ICMP does not
    /// use.
    fn from(sa: SocketAddrV6) -> Self {
        Self {
            addr: *sa.ip(),
            scope_id: sa.scope_id(),
        }
    }
}

impl From<ScopedIpv6Addr> for SocketAddrV6 {
    /// Port 0 and flow info 0.
    fn from(a: ScopedIpv6Addr) -> Self {
        SocketAddrV6::new(a.addr, 0, 0, a.scope_id)
    }
}

impl fmt::Display for ScopedIpv6Addr {
    /// `fe80::1%3`; without `%` for scope 0.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.scope_id == 0 {
            write!(f, "{}", self.addr)
        } else {
            write!(f, "{}%{}", self.addr, self.scope_id)
        }
    }
}

/// Why a string is not a scoped IPv6 address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopedAddrParseError {
    /// The part before `%` is not an IPv6 address.
    InvalidAddress,
    /// The part after `%` is neither a number nor the name of an interface
    /// on this host.
    UnknownInterface(String),
}

impl fmt::Display for ScopedAddrParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAddress => write!(f, "invalid IPv6 address"),
            Self::UnknownInterface(name) => write!(f, "unknown interface {:?}", name),
        }
    }
}

impl std::error::Error for ScopedAddrParseError {}

impl FromStr for ScopedIpv6Addr {
    type Err = ScopedAddrParseError;

    /// Parses `addr`, `addr%index` or `addr%interface-name`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, scope) = match s.split_once('%') {
            Some((addr, scope)) => (addr, Some(scope)),
            None => (s, None),
        };
        let addr: Ipv6Addr = addr
            .parse()
            .map_err(|_| ScopedAddrParseError::InvalidAddress)?;
        let scope_id = match scope {
            None => 0,
            Some(scope) => match scope.parse::<u32>() {
                Ok(index) => index,
                Err(_) => interface_index(scope)
                    .map_err(|_| ScopedAddrParseError::UnknownInterface(scope.to_owned()))?,
            },
        };
        Ok(Self { addr, scope_id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The loopback interface's name on this system.
    fn loopback_name() -> &'static str {
        if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        }
    }

    #[test]
    fn parses_numeric_and_named_scopes() {
        let a: ScopedIpv6Addr = "fe80::1%7".parse().unwrap();
        assert_eq!(a, ScopedIpv6Addr::new("fe80::1".parse().unwrap(), 7));
        assert_eq!(a.to_string(), "fe80::1%7");

        let lo = loopback_name();
        let named: ScopedIpv6Addr = format!("fe80::1%{}", lo).parse().unwrap();
        assert_ne!(named.scope_id, 0);
        assert_eq!(named.interface_name().unwrap().as_deref(), Some(lo));

        let plain: ScopedIpv6Addr = "::1".parse().unwrap();
        assert_eq!(plain.scope_id, 0);
        assert_eq!(plain.interface_name().unwrap(), None);
        assert_eq!(plain.to_string(), "::1");
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(
            "nope%1".parse::<ScopedIpv6Addr>(),
            Err(ScopedAddrParseError::InvalidAddress)
        );
        assert_eq!(
            "fe80::1%no-such-interface0".parse::<ScopedIpv6Addr>(),
            Err(ScopedAddrParseError::UnknownInterface(
                "no-such-interface0".into()
            ))
        );
        assert!(ScopedIpv6Addr::on_interface(Ipv6Addr::LOCALHOST, "a\0b").is_err());
    }

    #[test]
    fn converts_from_socket_addr() {
        let sa = SocketAddrV6::new("fe80::2".parse().unwrap(), 99, 5, 4);
        let a = ScopedIpv6Addr::from(sa);
        assert_eq!(a.scope_id, 4);
        assert_eq!(SocketAddrV6::from(a), SocketAddrV6::new(a.addr, 0, 0, 4));
    }
}
