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
use std::convert::From;
use std::net::{Ipv4Addr, Ipv6Addr};

use packet::{Builder, Packet as P};
use packet::icmp::echo::Packet;

// TODO(jwall): It turns out that the ICMPv6 packets are sufficiently
// different from the ICMPv4 packets. In order to handle them appropriately
// It is going to take some consideration.
use crate::{IcmpSocket4, IcmpSocket6};

pub struct EchoResponse {
    identifier: u16,
    sequence: u16,
    payload: Vec<u8>,
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