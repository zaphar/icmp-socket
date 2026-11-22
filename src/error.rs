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
