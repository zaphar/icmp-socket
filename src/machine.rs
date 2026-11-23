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
//! The I/O-free state machines behind every socket operation.
//!
//! A [`Machine`] holds every decision of a send or receive. It never
//! waits; a driver waits, then lets the machine run its pending
//! non-blocking call on the descriptor. The crate's blocking and async
//! sockets are drivers. Any other runtime can drive a machine too: split a
//! socket with `into_parts`, register the descriptor with the runtime, and
//! loop:
//!
//! ```no_run
//! use icmp_socket::machine::{Operation, Machine, Next, Progress};
//! # fn wait_until_ready(_: &std::os::fd::OwnedFd, _: Operation) {}
//!
//! # fn example() -> std::io::Result<()> {
//! let (fd, mut state) = icmp_socket::DgramSocket4::open()?.into_parts();
//! let mut machine = state.recv_from();
//! let reply = loop {
//!     match machine.next() {
//!         Next::Done(result) => break result,
//!         Next::Io(Operation::None) => {
//!             machine.perform(std::os::fd::AsFd::as_fd(&fd));
//!         }
//!         Next::Io(operation) => {
//!             wait_until_ready(&fd, operation); // the runtime's wait
//!             if let Progress::WouldBlock = machine.perform(std::os::fd::AsFd::as_fd(&fd)) {
//!                 // the runtime clears its readiness here, if it needs to
//!             }
//!         }
//!     }
//! };
//! # let _ = reply;
//! # Ok(())
//! # }
//! ```
use std::io;
use std::os::fd::BorrowedFd;

/// The kind of call a machine runs next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// A read: wait until the descriptor is readable or has an error to
    /// report.
    Read,
    /// A write: wait until the descriptor is writable.
    Write,
    /// A call that does not wait (e.g. setting an option): run it at once.
    None,
}

/// The next step of a machine.
#[derive(Debug)]
pub enum Next<T> {
    /// Wait until the descriptor is ready for the operation, then call
    /// [`Machine::perform`].
    Io(Operation),
    /// The result of the send or receive. The machine is finished; do not use
    /// it again.
    Done(T),
}

/// The result of one [`Machine::perform`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    /// The call ran; ask [`Machine::next`] what comes next.
    Continue,
    /// The descriptor was not ready. Wait until it is (and clear the runtime's
    /// readiness, if it needs that), then call `perform` again.
    WouldBlock,
}

/// A send or receive as an I/O-free state machine.
pub trait Machine {
    /// The operation's result.
    type Output;

    /// The next step. Call it until it returns [`Next::Done`], and not after.
    fn next(&mut self) -> Next<Self::Output>;

    /// Run the pending non-blocking call on `fd`. Every result except "not
    /// ready" goes into the machine, and [`Self::next`] reports the outcome.
    fn perform(&mut self, fd: BorrowedFd<'_>) -> Progress;

    /// An error from the driver's own wait (e.g. the reactor failed, or the
    /// driver's timeout expired: pass `io::ErrorKind::TimedOut`). The
    /// machine finishes with it.
    fn fail(&mut self, err: io::Error);
}
