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
use std::convert::{From, TryFrom, TryInto};

use socket2::SockAddr;

use crate::{
    packet::{Icmpv4Message, Icmpv4Packet, Icmpv6Message, Icmpv6Packet, WithEchoRequest},
    socket::IcmpSocket,
};

#[derive(Debug)]
pub struct EchoResponse {
    pub identifier: u16,
    pub sequence: u16,
    pub payload: Vec<u8>,
}

impl TryFrom<Icmpv6Packet> for EchoResponse {
    type Error = std::io::Error;

    fn try_from(pkt: Icmpv6Packet) -> Result<Self, Self::Error> {
        if let Icmpv6Message::EchoReply {
            identifier,
            sequence,
            payload,
        } = pkt.message
        {
            Ok(EchoResponse {
                identifier,
                sequence,
                payload,
            })
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "Incorrect icmpv6 message: {:?}, code: {}",
                    pkt.message, pkt.code
                ),
            ))
        }
    }
}

impl TryFrom<Icmpv4Packet> for EchoResponse {
    type Error = std::io::Error;

    fn try_from(pkt: Icmpv4Packet) -> Result<Self, Self::Error> {
        if let Icmpv4Message::EchoReply {
            identifier,
            sequence,
            payload,
        } = pkt.message
        {
            Ok(EchoResponse {
                identifier,
                sequence,
                payload,
            })
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "Incorrect icmpv4 message: {:?}, code: {}",
                    pkt.message, pkt.code
                ),
            ))
        }
    }
}

pub struct EchoSocket<S> {
    sequence: u16,
    inner: S,
}

// TODO(jwall): Make this a trait
impl<S> EchoSocket<S>
where
    S: IcmpSocket,
    S::PacketType: WithEchoRequest<Packet = S::PacketType>
        + TryInto<EchoResponse, Error = std::io::Error>
        + std::fmt::Debug,
{
    pub fn new(sock: S) -> Self {
        EchoSocket {
            inner: sock,
            sequence: 0,
        }
    }

    pub fn set_max_hops(&mut self, hops: u32) {
        self.inner.set_max_hops(hops);
    }

    pub fn send_ping(
        &mut self,
        dest: S::AddrType,
        identifier: u16,
        payload: &[u8],
    ) -> std::io::Result<()> {
        let packet =
            S::PacketType::with_echo_request(identifier, self.sequence, payload.to_owned())?;
        self.sequence += 1;
        self.inner.send_to(dest, packet)?;
        Ok(())
    }

    pub fn recv_ping(&mut self) -> std::io::Result<(EchoResponse, SockAddr)> {
        let (packet, addr) = self.inner.rcv_from()?;
        Ok((packet.try_into()?, addr))
    }
}

impl<S> From<S> for EchoSocket<S>
where
    S: IcmpSocket,
    S::PacketType: WithEchoRequest<Packet = S::PacketType>
        + TryInto<EchoResponse, Error = std::io::Error>
        + std::fmt::Debug,
{
    fn from(sock: S) -> Self {
        EchoSocket::new(sock)
    }
}
