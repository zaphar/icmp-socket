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

use std::convert::{TryFrom, Into, TryInto};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use socket2::{Socket, Domain, Type, Protocol};

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

    pub fn send_to(&mut self, dest: Ipv4Addr, payload: &[u8]) -> std::io::Result<()> {
        //let packet = packet::icmp::Builder::default()
        //    .echo().unwrap().request().unwrap().identifier(42).unwrap().sequence(seq)
        //    .unwrap().payload(payload).unwrap().build().unwrap();
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

    pub fn send_to(&mut self, dest: Ipv6Addr, payload: &[u8]) -> std::io::Result<()> {
        //let packet = packet::icmp::Builder::default()
        //    .echo().unwrap().request().unwrap().identifier(42).unwrap().sequence(seq)
        //    .unwrap().payload(payload).unwrap().build().unwrap();
        let dest = ip_to_socket(&IpAddr::V6(dest));
        self.inner.set_unicast_hops_v6(self.opts.hops)?;
        self.inner.send_to(&payload, &(dest.into()))?;
        Ok(())
    }
    
    
    pub fn rcv_from(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let (read_count, _addr) = self.inner.recv_from(buf)?;
        Ok(read_count)
    }
}

pub enum IcmpSocket {
    V4(IcmpSocket4),
    V6(IcmpSocket6),
}

use IcmpSocket::{V4, V6};

impl IcmpSocket {
    pub fn new_v4() -> std::io::Result<Self> {
        Ok(V4(IcmpSocket4::new()?))        
    }
    
    pub fn new_v6() -> std::io::Result<Self> {
        Ok(V6(IcmpSocket6::new()?))        
    }

    pub fn with_ip(ip: IpAddr) -> std::io::Result<Self>  {
        ip.try_into()
    }

    pub fn set_max_hops(&mut self, hops: u32) {
        match self {
            V4(ref mut s) => s.set_max_hops(hops),
            V6(ref mut s) => s.set_max_hops(hops),
        }
    }
    pub fn send_to(&mut self, dest: IpAddr, payload: &[u8]) -> std::io::Result<()> {
        match dest {
            IpAddr::V4(ip) => if let V4(ref mut sock) = self {
                sock.send_to(ip, payload)?;
            } else {
                return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("Attempt to send to IPv4 dest {} from IPv6 source", ip)));
            },
            IpAddr::V6(ip) => if let V6(ref mut sock) = self {
                sock.send_to(ip, payload)?;
            } else {
                return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("Attempt to send to IPv6 dest {} from IPv4 source", ip)));
            },
        }
        Ok(())
    }

    pub fn rcv_from(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            V4(ref s) => s.rcv_from(buf),
            V6(ref s) => s.rcv_from(buf),
        }
    }
}

impl TryFrom<IpAddr> for IcmpSocket {
    type Error = std::io::Error;

    fn try_from(addr: IpAddr) -> Result<Self, Self::Error> {
        match addr {
           IpAddr::V4(addr) => addr.try_into(),
           IpAddr::V6(addr) => addr.try_into(),
        }
    }
}

impl TryFrom<Ipv4Addr> for IcmpSocket {
    type Error = std::io::Error;

    fn try_from(addr: Ipv4Addr) -> Result<Self, Self::Error> {
        let mut sock = IcmpSocket4::new()?;
        sock.bind(addr)?;
        Ok(IcmpSocket::V4(sock)) 
    }
}

impl TryFrom<Ipv6Addr> for IcmpSocket {
    type Error = std::io::Error;

    fn try_from(addr: Ipv6Addr) -> Result<Self, Self::Error> {
        let mut sock = IcmpSocket6::new()?;
        sock.bind(addr)?;
        Ok(IcmpSocket::V6(sock)) 
    }
}
