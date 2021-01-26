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
use std::net::Ipv6Addr;

use icmp_socket::socket::IcmpSocket;
use icmp_socket::*;

pub fn main() {
    let mut socket6 = IcmpSocket6::new().unwrap();
    socket6.bind("::1".parse::<Ipv6Addr>().unwrap()).unwrap();
    let mut echo_socket = echo::EchoSocket6::new(socket6);
    echo_socket
        .send_ping(
            "::1".parse::<Ipv6Addr>().unwrap(),
            42,
            &[
                0x20, 0x20, 0x75, 0x73, 0x74, 0x20, 0x61, 0x20, 0x66, 0x6c, 0x65, 0x73, 0x68, 0x20,
                0x77, 0x6f, 0x75, 0x6e, 0x64, 0x20, 0x20, 0x74, 0x69, 0x73, 0x20, 0x62, 0x75, 0x74,
                0x20, 0x61, 0x20, 0x73, 0x63, 0x72, 0x61, 0x74, 0x63, 0x68, 0x20, 0x20, 0x6b, 0x6e,
                0x69, 0x67, 0x68, 0x74, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x6e, 0x69, 0x20, 0x20, 0x20,
            ],
        )
        .unwrap();
    let _ = echo_socket.recv_ping();
    let resp = echo_socket.recv_ping().unwrap();
    println!(
        "seq: {}, identifier: {} payload: {}",
        resp.sequence,
        resp.identifier,
        resp.payload.len()
    );
}
