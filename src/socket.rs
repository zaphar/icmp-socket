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

use std::convert::{TryFrom, Into};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use socket2::{Socket, Domain, Type, Protocol};

use crate::packet::Icmpv6Packet;

fn ip_to_socket(ip: &IpAddr) -> SocketAddr {
    format!("{}:0", ip).parse::<SocketAddr>().unwrap()
}

pub struct Opts {
    hops: u32,
}

pub struct IcmpSocket4 {
    bound_to: Option<Ipv4Addr>,
    inner: Socket,
    opts: Opts,
}

impl IcmpSocket4 {
    pub fn new() -> std::io::Result<Self> {
        Ok(Self{
            bound_to: None,
            inner: Socket::new(Domain::ipv4(), Type::raw(), Some(Protocol::icmpv4()))?,
            opts: Opts{ hops: 50 },
        })
    }

    pub fn set_max_hops(&mut self, hops: u32) {
        self.opts.hops = hops;
    }
    
    pub fn bind<A: Into<Ipv4Addr>>(&mut self, addr: A) -> std::io::Result<()> {
        let addr = addr.into();
        self.bound_to = Some(addr.clone());
        let sock = ip_to_socket(&IpAddr::V4(addr));
        self.inner.bind(&(sock.into()))?;
        Ok(())
    }

    // TODO(jwall): This should take an actual packet not the payload.
    pub fn send_to(&mut self, dest: Ipv4Addr, payload: &[u8]) -> std::io::Result<()> {
        let dest = ip_to_socket(&IpAddr::V4(dest));
        self.inner.set_ttl(self.opts.hops)?;
        self.inner.send_to(payload, &(dest.into()))?;
        Ok(())
    }
    
    pub fn rcv_from(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let (read_count, _addr) = self.inner.recv_from(buf)?;
        Ok(read_count)
    }
}

pub struct IcmpSocket6 {
    bound_to: Option<Ipv6Addr>,
    inner: Socket,
    opts: Opts,
}

impl IcmpSocket6 {
    pub fn new()-> std::io::Result<Self> {
        Ok(Self{
            bound_to: None,
            inner: Socket::new(Domain::ipv6(), Type::raw(), Some(Protocol::icmpv6()))?,
            opts: Opts{ hops: 50 },
        })
    }

    pub fn set_max_hops(&mut self, hops: u32) {
        self.opts.hops = hops;
    }
    
    pub fn bind<A: Into<Ipv6Addr>>(&mut self, addr: A) -> std::io::Result<()> {
        let addr = addr.into();
        self.bound_to = Some(addr.clone());
        let sock = ip_to_socket(&IpAddr::V6(addr));
        self.inner.bind(&(sock.into()))?;
        Ok(())
    }

    // TODO(jwall): This should take an actual packet not the payload.
    pub fn send_to(&mut self, dest: Ipv6Addr, mut packet: Icmpv6Packet) -> std::io::Result<()> {
        let source = match self.bound_to {
            Some(ref addr) => addr,
            None => return Err(std::io::Error::new(std::io::ErrorKind::Other, "Socket not bound to an address")),
        };
        packet = packet.with_checksum(source, &dest);
        let dest = ip_to_socket(&IpAddr::V6(dest));
        self.inner.set_unicast_hops_v6(self.opts.hops)?;
        self.inner.send_to(&packet.get_bytes(true), &(dest.into()))?;
        Ok(())
    }
   
    // TODO(jwall): This should return a packet not bytes.
    pub fn rcv_from(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let (read_count, _addr) = self.inner.recv_from(buf)?;
        Ok(read_count)
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
