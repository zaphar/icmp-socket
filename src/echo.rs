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
use std::convert::{TryFrom, From, TryInto};
use std::net::{Ipv4Addr, Ipv6Addr};

use packet::{Builder, Packet as P};
use packet::icmp::echo::Packet;

use crate::packet::{Icmpv6Packet, Icmpv6Message::EchoReply};

// TODO(jwall): It turns out that the ICMPv6 packets are sufficiently
// different from the ICMPv4 packets. In order to handle them appropriately
// It is going to take some consideration.
use crate::{IcmpSocket4, IcmpSocket6};

#[derive(Debug)]
pub struct EchoResponse {
    pub identifier: u16,
    pub sequence: u16,
    pub payload: Vec<u8>,
}

impl TryFrom<Icmpv6Packet> for EchoResponse {
    type Error = std::io::Error;

    fn try_from(pkt: Icmpv6Packet) -> Result<Self, Self::Error> {
        if let EchoReply{
            identifier,
            sequence,
            payload,
        } = pkt.message {
            Ok(EchoResponse{
                identifier,
                sequence,
                payload,
            })
        } else {
            Err(std::io::Error::new(std::io::ErrorKind::Other, format!("Incorrect icmpv6 message: {:?}, code: {}", pkt.message, pkt.code)))
        }
    }
}

pub struct EchoSocket4 {
    sequence: u16,
    buf: Vec<u8>,
    inner: IcmpSocket4,
}

impl EchoSocket4 {
    pub fn new(sock: IcmpSocket4) -> Self {
        EchoSocket4{inner:sock, sequence: 0, buf: Vec::with_capacity(512)}
    }

    pub fn set_max_hops(&mut self, hops: u32) {
        self.inner.set_max_hops(hops);
    }

    pub fn send_ping(&mut self, dest: Ipv4Addr, identifier: u16, payload: &[u8]) -> std::io::Result<()> {
        let packet = packet::icmp::Builder::default()
            .echo().unwrap().request().unwrap()
            .identifier(identifier).unwrap()
            .sequence(self.sequence).unwrap()
            .payload(payload).unwrap().build().unwrap();
        self.sequence += 1;
        self.inner.send_to(dest, &packet)?;
        Ok(())
    }

    pub fn recv_ping(&mut self) -> std::io::Result<EchoResponse> {
        let bytes_read = self.inner.rcv_from(&mut self.buf)?;
        match Packet::new(&self.buf[0..bytes_read]) {
            Ok(p) => return Ok(EchoResponse{
                sequence: p.sequence(),
                identifier: p.identifier(),
                payload: p.payload().to_owned(),
            }),
            Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("Malformed ICMP Response: {:?}", e))),
        };
    }
}

impl From<IcmpSocket4> for EchoSocket4 {
    fn from(sock: IcmpSocket4) -> Self {
        EchoSocket4::new(sock)
    }
}

pub struct EchoSocket6 {
    sequence: u16,
    inner: IcmpSocket6,
}

impl EchoSocket6 {

    pub fn new(sock: IcmpSocket6) -> Self {
        // TODO(jwall): How to set ICMPv6 filters.
        EchoSocket6{inner:sock, sequence: 0}
    }

    pub fn set_max_hops(&mut self, hops: u32) {
        self.inner.set_max_hops(hops);
    }

    pub fn send_ping(&mut self, dest: Ipv6Addr, identifier: u16, payload: &[u8]) -> std::io::Result<()> {
        let packet = Icmpv6Packet::with_echo_request(identifier, self.sequence, payload.to_owned())?;
        self.sequence += 1;
        self.inner.send_to(dest, packet)?;
        Ok(())
    }

    pub fn recv_ping(&mut self) -> std::io::Result<EchoResponse> {
        let pkt = self.inner.rcv_from()?;
        Ok(pkt.try_into()?)
    }
}

impl From<IcmpSocket6> for EchoSocket6 {
    fn from(sock: IcmpSocket6) -> Self {
        EchoSocket6::new(sock)
    }
}
