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
use std::{
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use icmp_socket::packet::WithEchoRequest;
use icmp_socket::socket::IcmpSocket;
use icmp_socket::*;

pub fn main() {
    let address = std::env::args().nth(1).unwrap_or("127.0.0.1".to_owned());
    let parsed_addr = address.parse::<Ipv4Addr>().unwrap();
    let packet_handler = |pkt: Icmpv4Packet, send_time: Instant, addr: Ipv4Addr| -> Option<()> {
        let now = Instant::now();
        let elapsed = now - send_time;
        if addr == parsed_addr {
            // TODO
            if let Icmpv4Message::EchoReply {
                identifier: _,
                sequence,
                payload,
            } = pkt.message
            {
                println!(
                    "Ping {} seq={} time={}ms size={}",
                    addr,
                    sequence,
                    (elapsed.as_micros() as f64) / 1000.0,
                    payload.len()
                );
            } else {
                //eprintln!("Discarding non-reply {:?}", pkt);
                return None;
            }
            Some(())
        } else {
            eprintln!("Discarding packet from {}", addr);
            None
        }
    };
    let mut socket4 = IcmpSocket4::new().unwrap();
    socket4
        .bind("0.0.0.0".parse::<Ipv4Addr>().unwrap())
        .unwrap();
    // TODO(jwall): The first packet we recieve will be the one we sent.
    // We need to implement packet filtering for the socket.
    let mut sequence = 0 as u16;
    loop {
        let packet = Icmpv4Packet::with_echo_request(
            42,
            sequence,
            vec![
                0x20, 0x20, 0x75, 0x73, 0x74, 0x20, 0x61, 0x20, 0x66, 0x6c, 0x65, 0x73, 0x68, 0x20,
                0x77, 0x6f, 0x75, 0x6e, 0x64, 0x20, 0x20, 0x74, 0x69, 0x73, 0x20, 0x62, 0x75, 0x74,
                0x20, 0x61, 0x20, 0x73, 0x63, 0x72, 0x61, 0x74, 0x63, 0x68, 0x20, 0x20, 0x6b, 0x6e,
                0x69, 0x67, 0x68, 0x74, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x6e, 0x69, 0x20, 0x20, 0x20,
            ],
        )
        .unwrap();
        let send_time = Instant::now();
        socket4
            .send_to(address.parse::<Ipv4Addr>().unwrap(), packet)
            .unwrap();
        socket4.set_timeout(Duration::from_secs(1)).unwrap();
        loop {
            let (resp, sock_addr) = match socket4.rcv_from() {
                Ok(tpl) => tpl,
                Err(e) => {
                    eprintln!("{:?}", e);
                    break;
                }
            };
            if packet_handler(resp, send_time, *sock_addr.as_socket_ipv4().unwrap().ip()).is_some()
            {
                std::thread::sleep(Duration::from_secs(1));
                break;
            }
        }
        sequence = sequence.wrapping_add(1);
    }
}
