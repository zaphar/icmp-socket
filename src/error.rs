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
//! Errors from parsing and building messages.
use std::fmt;

/// Why bytes could not be parsed as an ICMP message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Fewer bytes than the message type's fixed layout needs.
    TooShort { needed: usize, actual: usize },
    /// A fixed-length message type with bytes after its end.
    TrailingBytes { expected: usize, actual: usize },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::TooShort { needed, actual } => write!(
                f,
                "ICMP message too short: {} bytes, needs at least {}",
                actual, needed
            ),
            ParseError::TrailingBytes { expected, actual } => write!(
                f,
                "ICMP message has trailing bytes: {} bytes, the type is exactly {}",
                actual, expected
            ),
        }
    }
}

impl std::error::Error for ParseError {}

/// An `Other` message was built for a type number the crate models with its
/// own variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelledTypeError {
    /// The type number.
    pub typ: u8,
}

impl fmt::Display for ModelledTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ICMP type {} has its own variant and cannot be an Other message",
            self.typ
        )
    }
}

impl std::error::Error for ModelledTypeError {}

/// The `ParseError` is kept inside the `io::Error`; recover it with
/// `get_ref()` and `downcast_ref::<ParseError>()`.
impl From<ParseError> for std::io::Error {
    fn from(err: ParseError) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, err)
    }
}

/// Why a receive failed.
///
/// `P` holds the failures only one protocol has: [`Ipv4RecvError`] for
/// ICMPv4 sockets and [`std::convert::Infallible`] for ICMPv6 sockets, so a
/// `match` on an ICMPv6 receive error can leave out the `Protocol` arm.
#[derive(Debug)]
pub enum RecvError<P> {
    /// The operating system reported an error.
    Io(std::io::Error),
    /// The socket's read timeout expired.
    Timeout,
    /// The message was larger than the socket's maximum message size and
    /// was truncated; see `set_max_message_size`.
    Truncated { buf_size: usize },
    /// The message could not be parsed.
    Parse(ParseError),
    /// A failure only this protocol has.
    Protocol(P),
}

/// Receive failures only ICMPv4 sockets have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv4RecvError {
    /// The IPv4 header the system delivered before the message is invalid.
    InvalidIpHeader,
    /// The message's checksum is wrong. (ICMPv6 sockets never see this: the
    /// kernel drops such packets.)
    BadChecksum,
}

impl<P: fmt::Display> fmt::Display for RecvError<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecvError::Io(e) => write!(f, "{}", e),
            RecvError::Timeout => write!(f, "receive timed out"),
            RecvError::Truncated { buf_size } => write!(
                f,
                "received message was larger than the {} byte maximum message size and was truncated",
                buf_size
            ),
            RecvError::Parse(e) => write!(f, "{}", e),
            RecvError::Protocol(e) => write!(f, "{}", e),
        }
    }
}

impl<P: std::error::Error + 'static> std::error::Error for RecvError<P> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RecvError::Io(e) => Some(e),
            RecvError::Parse(e) => Some(e),
            RecvError::Protocol(e) => Some(e),
            RecvError::Timeout | RecvError::Truncated { .. } => None,
        }
    }
}

impl fmt::Display for Ipv4RecvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ipv4RecvError::InvalidIpHeader => write!(f, "invalid IPv4 header"),
            Ipv4RecvError::BadChecksum => write!(f, "bad ICMP checksum"),
        }
    }
}

impl std::error::Error for Ipv4RecvError {}

/// `Io(e)` becomes `e`. Every other variant is kept inside the `io::Error`
/// (recover it with `get_ref()` and `downcast_ref`): `Timeout` has kind
/// `TimedOut`, and `Truncated`, `Parse` and `Protocol` have kind
/// `InvalidData`.
impl<P> From<RecvError<P>> for std::io::Error
where
    P: std::error::Error + Send + Sync + 'static,
{
    fn from(err: RecvError<P>) -> Self {
        match err {
            RecvError::Io(e) => e,
            RecvError::Timeout => std::io::Error::new(std::io::ErrorKind::TimedOut, err),
            other => std::io::Error::new(std::io::ErrorKind::InvalidData, other),
        }
    }
}

impl<P> From<ParseError> for RecvError<P> {
    fn from(err: ParseError) -> Self {
        RecvError::Parse(err)
    }
}
