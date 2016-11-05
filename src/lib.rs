// Copyright 2016 Mazdak Farrokhzad.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! # tor_control
//!
//! Client interface to the [Tor Control Protocol], hence referenced as TorCP.
//!
//! The `tor_control` module contains the [`TorControl`] struct used to connect
//! to TorCP, and various types for error handling, and implementations of
//! `std` traits for error handling.
//!
//! [`TorControl`]: struct.TorControl.html
//! [Tor Control Protocol]: https://gitweb.torproject.org/torspec.git/tree/control-spec.txt

//============================================================================//
// Imports + Features                                                         //
//============================================================================//

#![feature(try_from)]

// BufStream:
extern crate bufstream;
use bufstream::BufStream;

use std::iter;

// Standard Library:
use std::io::{self, Write, Read, BufRead};
use std::net::{ToSocketAddrs, TcpStream};
use std::str;
use std::fmt::{self, Display, Debug, Formatter};
use std::convert::{TryFrom, TryInto};
use std::error::Error;

//============================================================================//
// Errors:                                                                    //
//============================================================================//

/// The kinds of errors that TorCP can issue as specified in `4. Replies` in the
/// TorCP specification. Note that codes `250`, `251` and `651` are not errors.
#[derive(Debug)]
pub enum TCErrorKind {
    ResourceExhausted,
    SyntaxErrorProtocol,
    UnrecognizedCmd,
    UnimplementedCmd,
    SyntaxErrorCmdArg,
    UnrecognizedCmdArg,
    AuthRequired,
    BadAuth,
    UnspecifiedTorError,
    InternalError,
    UnrecognizedEntity,
    InvalidConfigValue,
    InvalidDescriptor,
    UnmanagedEntity,
}

/// The types of errors that can come as a result of interacting with TorCP.
#[derive(Debug)]
pub enum TCError {
    /// Wraps [`io:Error`](https://doc.rust-lang.org/std/io/struct.Error.html).
    IoError(io::Error),
    /// Indicates an unknown error code.
    UnknownResponse,
    /// Wraps **error** status codes that TorCP replies with.
    /// `250` and `251` are not errors, and thus is an `Ok(_)`.
    TorError(TCErrorKind)
}

/// The type of `Result` that the interface deals with. [E = `TCError`].
/// [E = `TCError`]: enum.TCError.html
pub type TCResult<X> = Result<X, TCError>;

use self::TCErrorKind::*;
use self::TCError::*;

/// Conversions from `TCErrorKind` into the actual error code as specified in
/// `4. Replies` in the TorCP specification.
impl Into<u32> for TCErrorKind {
    fn into(self) -> u32 {
        match self {
            ResourceExhausted    => 451,
            SyntaxErrorProtocol  => 500,
            UnrecognizedCmd      => 510,
            UnimplementedCmd     => 511,
            SyntaxErrorCmdArg    => 512,
            UnrecognizedCmdArg   => 513,
            AuthRequired         => 514,
            BadAuth              => 515,
            UnspecifiedTorError  => 550,
            InternalError        => 551,
            UnrecognizedEntity   => 552,
            InvalidConfigValue   => 553,
            InvalidDescriptor    => 554,
            UnmanagedEntity      => 555,
        }
    }
}

/// Conversions from error codes into as specified in
/// `4. Replies` in the TorCP specification.
impl TryFrom<u32> for TCErrorKind {
    type Err = ();
    fn try_from(code: u32) -> Result<Self, ()> {
        match code {
            451 => Ok(ResourceExhausted),
            500 => Ok(SyntaxErrorProtocol),
            510 => Ok(UnrecognizedCmd),
            511 => Ok(UnimplementedCmd),
            512 => Ok(SyntaxErrorCmdArg),
            513 => Ok(UnrecognizedCmdArg),
            514 => Ok(AuthRequired),
            515 => Ok(BadAuth),
            550 => Ok(UnspecifiedTorError),
            551 => Ok(InternalError),
            552 => Ok(UnrecognizedEntity),
            553 => Ok(InvalidConfigValue),
            554 => Ok(InvalidDescriptor),
            555 => Ok(UnmanagedEntity),
            _   => Err(())
        }
    }
}

/// `Display` for `TCError` simply uses `Debug`.
impl Display for TCError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Debug::fmt(self, f)
    }
}

impl Error for TCError {
    fn description(&self) -> &str {
        match *self {
            IoError(ref e)      => e.description(),
            UnknownResponse     => "Tor Control replied with unknown response",
            TorError(ref kind)  => match *kind {
                ResourceExhausted   => "Tor Control: Resource exhausted",
                SyntaxErrorProtocol => "Tor Control: Syntax error: protocol",
                UnrecognizedCmd     => "Tor Control: Unrecognized command",
                UnimplementedCmd    => "Tor Control: Unimplemented command",
                SyntaxErrorCmdArg   => "Tor Control: Syntax error in command argument",
                UnrecognizedCmdArg  => "Tor Control: Unrecognized command argument",
                AuthRequired        => "Tor Control: Authentication required",
                BadAuth             => "Tor Control: Bad authentication",
                UnspecifiedTorError => "Tor Control: Unspecified Tor error",
                InternalError       => "Tor Control: Internal error",
                UnrecognizedEntity  => "Tor Control: Unrecognized entity",
                InvalidConfigValue  => "Tor Control: Invalid configuration value",
                InvalidDescriptor   => "Tor Control: Invalid descriptor",
                UnmanagedEntity     => "Tor Control: Unmanaged entity",
            }
        }
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            IoError(ref e) => Some(e),
            _              => None
        }
    }
}

impl From<io::Error> for TCError {
    fn from(err: io::Error) -> TCError {
        TCError::IoError(err)
    }
}

impl From<u32> for TCError {
    fn from(err: u32) -> TCError {
        err.try_into().map(TorError).unwrap_or(UnknownResponse)
    }
}

//============================================================================//
// Structs:                                                                   //
//============================================================================//

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::sync::mpsc::{channel, Receiver, Sender, SendError};

pub type Event = u32;

/// Used for `SETEVENTS` (see: `3.4`, `4.1`).
///
/// It consists of two parts:
///
/// - `evt_tx`: The [`Sender`] half of the channel used by [`setevents`].
///   This is protected by a mutex ensuring, that when a sync command is being
///   sent, the all replies (both async and sync) are handled by the method
///   that sent it, and not the async-replies handler thread.
///   To ensure this, the lock is held by such methods from before the command
///   is sent and until the last sync command is received.
///
/// - `close`: A close switch for the async-replies handler thread. Changing to
///   `true` closes the thread. This is only used internally in [`setevents`].
///
/// [`setevents`]: struct.TorControl.html#method.setevents
/// [`Sender`]: https://doc.rust-lang.org/std/sync/mpsc/struct.Sender.html
pub struct AsyncState {
    evt_tx: Mutex<Sender<Event>>,
    close:  AtomicBool
}

/// TorControl data structure.
/// Holds a `BufStream` to a stream `T`, which is often a `TcpStream`.
/// In addition, it records if TorCP is authenticated or not.
pub struct TorControl<T: Read + Write> {
    /// The buffered stream used to communicate with TorCP.
    stream:  BufStream<T>,
    /// Records if we've authenticated with TorCP yet.
    is_auth: bool,
    /// The transmitter half for async events (4.1, and enabled by 3.4).
    asyncs:  Option<Arc<AsyncState>>
}

//============================================================================//
// Internal / Macros:                                                         //
//============================================================================//

/// Does a bunch of `write_all(...)` on a Write.
macro_rules! try_write {
    ( $s:expr, $( $x:expr ),* ) => {
        $( try!($s.write_all( $x )); )*
    };
}

/// Writes end of line and flushes on a Write.
fn write_end<W: Write>(w: &mut W) -> TCResult<()> {
    try_write!(w, b"\r\n");
    try!(w.flush());
    Ok(())
}

/// Combines `try_write!(...)` and `write_end` on a Write.
macro_rules! try_wend {
    ( $s:expr ) => { try!(write_end(&mut $s)) };
    ( $s:expr, $( $x:expr ),* ) => {
        try_write!( $s, $($x),* );
        try!(write_end(&mut $s))
    };
}

//============================================================================//
// Internal / Free helper functions:                                          //
//============================================================================//

/// Converts a "string" to a u32, or fails with `UnknownResponse`.
fn str_to_u32<S: AsRef<str>>(s: S) -> TCResult<u32> {
    s.as_ref().parse().map_err(|_| UnknownResponse)
}

fn read_status<S: AsRef<str>>(line: S) -> TCResult<u32> {
    str_to_u32(&line.as_ref()[0 .. 3])
}

fn read_is_end<S: AsRef<str>>(line: S) -> TCResult<bool> {
    // Act upon separator:
    match &line.as_ref()[3 .. 4] {
        // Meaning: this is the last line to read.
        " "       => Ok(true),
        // We have more lines to read.
        "+" | "-" => Ok(false),
        _         => Err(UnknownResponse)
    }
}

fn read_line<'b, T>(stream: &mut BufStream<T>, buf: &'b mut String)
    -> TCResult<(u32, bool, &'b str)>
    where T: Read + Write {
    // Read a line and make sure we have at least 3 (status) + 1 (sep) bytes.
    if try!(stream.read_line(buf)) < 4 {
        return Err(UnknownResponse)
    }
    let (buf_s, msg) = buf.split_at(4);
    let status       = try!(read_status(&buf_s));
    let is_end       = try!(read_is_end(&buf_s));
    Ok((status, is_end, msg))
}

//============================================================================//
// Internal / Helper methods                                                  //
//============================================================================//

/// A guard for the sender, either its a real `MutexGuard`, or a fake.
type SenderGuard<'a> = Option<MutexGuard<'a, Sender<Event>>>;

/// `Event Sender` trait, to satisfy compiler.
trait ESend {
    fn send(&self, t: Event) -> Result<(), SendError<Event>>;
}

/// See `ESend`.
impl<'a> ESend for SenderGuard<'a> {
    fn send(&self, t: Event) -> Result<(), SendError<Event>> {
        match self {
            &None => Ok(()),
            &Some(ref real) => (*real).send(t)
        }
    }
}

fn handle_async<M: AsRef<str>>(sender: &SenderGuard, msg: M) -> TCResult<()> {
    unimplemented!();
}

struct TCLock<'a, T: 'a + Read + Write> {
    is_auth: &'a mut bool,
    stream:  &'a mut BufStream<T>,
    sender:  SenderGuard<'a>
}

impl<'a, T: Read + Write> TCLock<'a, T> {
    /// Handles a status code, 250 or 251 is Ok, otherwise error.
    fn handle_code(&mut self, status: u32) -> TCResult<()> {
        match status {
            250 | 251 => Ok(()),
            status    => match status.into() {
                TorError(AuthRequired) => {
                    *self.is_auth = false;
                    Err(TorError(AuthRequired))
                },
                e                      => Err(e)
            },
        }
    }

    /// Reads a status code, if `250` -> `Ok(())`, otherwise -> error.
    fn read_ok(&mut self) -> TCResult<()> {
        let mut buf = String::new();
        loop {
            {
                let (status, end, msg) = try!(read_line(self.stream, &mut buf));
                if status == 650 {
                    try!(handle_async(&self.sender, msg));
                } else if !end {
                    return Err(UnknownResponse);
                } else {
                    return self.handle_code(status);
                }
            }
            buf.clear();
        }
    }

    /// Reads one or many reply lines as specified in `2.3`.
    /// Terminates early on status code other than `250`.
    fn read_reply_lines(&mut self) -> TCResult<Vec<String>> {
        let mut rls: Vec<String> = Vec::with_capacity(1);
        let mut buf = String::new();
        loop {
            {
                let (status, end, msg) = try!(read_line(self.stream, &mut buf));
                if status == 650 {
                    try!(handle_async(&self.sender, msg));
                } else {
                    try!(self.handle_code(status));
                    rls.push(msg.trim_right().to_owned());
                    if end {
                        break;
                    }
                }
            }
            buf.clear();
        }

        Ok(rls)
    }
}

impl<T> TorControl<T> where T: Read + Write {
    /// If internal state is recorded as not auth, an error is "thrown".
    fn req_auth(&self) -> TCResult<()> {
        if self.is_auth {
            Ok(())
        } else {
            Err(TorError(AuthRequired))
        }
    }

    /// Returns a version of self that has exclusive write access to the stream.
    /// This access ends when the returned version is dropped.
    fn lock_tx<'a>(&'a mut self) -> TCLock<'a, T> {
        TCLock {
            is_auth: &mut self.is_auth,
            stream:  &mut self.stream,
            sender:  match self.asyncs {
                None => None,
                Some(ref astate) => Some(astate.evt_tx.lock().unwrap())
            }
        }
    }

    /// Executes a command that requires authentication and fails or
    /// responds with status code 250.
    fn authreq_command(&mut self, sig: &[u8]) -> TCResult<()> {
        try!(self.req_auth());
        let mut tclock = self.lock_tx();
        try_wend!(tclock.stream, sig);
        tclock.read_ok()
    }

    /// Writes an iterator of byte arrays to the stream, separated by whitespace.
    fn write_many<I, Is>(&mut self, items: Is) -> TCResult<usize>
        where I:  AsRef<[u8]>,
              Is: IntoIterator<Item = I> {
        let mut c = 0;
        for item in items.into_iter() {
            try_write!(self.stream, b" ", item.as_ref());
            c += 1;
        }
        Ok(c)
    }

    /// Used for `setconf` and `resetconf`.
    fn xsetconf<P>(&mut self, cmd: &[u8], kw: P, val: Option<P>) -> TCResult<()>
        where P: AsRef<[u8]> {
        try!(self.req_auth());

        try_wend!(self.stream, cmd, b" ", kw.as_ref());
        if let Some(value) = val {
            try_write!(self.stream, b" = ", value.as_ref());
        }

        let mut tclock = self.lock_tx();
        try_wend!(tclock.stream);
        tclock.read_ok()
    }
}

//============================================================================//
// Public API, specialization for TcpStream:                                  //
//============================================================================//

impl TorControl<TcpStream> {
    /// Connects to the TorCP at the specified address using TCP as
    /// backend protocol.
    pub fn connect<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        Ok(Self::new(try!(TcpStream::connect(addr))))
    }
}

//============================================================================//
// Public API:                                                                //
//============================================================================//

impl<T> TorControl<T> where T: Read + Write {
    /// Constructs an interface to TorCP given the backing stream of type `T`,
    /// which is most often a `TcpStream`.
    pub fn new(stream: T) -> Self {
        TorControl {
            stream:  BufStream::new(stream),
            is_auth: false,
            asyncs:  None,
        }
    }

    /// Returns true if we are authenticated.
    pub fn is_auth(&self) -> bool {
        self.is_auth
    }

    /// Authenticates to TorCP as specified in `3.5. AUTHENTICATE`.
    ///
    /// If no password is required, `mpass == None`, otherwise `Some("<pass>")`.
    pub fn auth<P>(&mut self, mpass: Option<P>) -> TCResult<()>
        where P: AsRef<[u8]> {
        if self.is_auth {
            return Ok(())
        }

        {
            let mut tclock = self.lock_tx();

            if let Some(pass) = mpass {
                try_wend!(tclock.stream, b"AUTHENTICATE ", pass.as_ref());
            } else {
                try_wend!(tclock.stream, b"AUTHENTICATE");
            }

            try!(tclock.read_ok());
        }

        self.is_auth = true;
        Ok(())
    }

    /// Sets a configuration as specified in `3.1. SETCONF`.
    ///
    /// It sets the configuration variable specified by `kw` to `value`
    /// when `val == Some(value)` is given. Otherwise, on `None`,
    /// it is reset to `0` or `NULL`.
    pub fn setconf<P>(&mut self, kw: P, val: Option<P>) -> TCResult<()>
        where P: AsRef<[u8]> {
        self.xsetconf(b"SETCONF", kw, val)
    }

    /// Sets a configuration as specified in `3.2. RESETCONF`.
    ///
    /// Behaves as [`setconf`] in every respect except for what happens when
    /// `val == None`. In that case, the configuration variable specified by
    /// `kw` is reset to the default value.
    ///
    /// [`setconf`]: struct.TorControl.html#method.setconf
    pub fn resetconf<P>(&mut self, kw: P, val: Option<P>) -> TCResult<()>
        where P: AsRef<[u8]> {
        self.xsetconf(b"RESETCONF", kw, val)
    }

    /// Gets a configuration as specified in `3.3. GETCONF`.
    ///
    /// Requests the value(s) of a configuration variable specified by keys `kws`.
    /// If any key does not correspond to a valid variable, an error is "thrown".
    /// 
    /// # Examples
    ///
    /// Let's assume that we have `torrc` file that includes, among other things:
    ///
    /// ```text
    /// SOCKSPolicy accept 127.0.0.1
    /// SOCKSPolicy reject *
    /// HashedControlPassword 16:1E4D6C2977B2413E60A8563914D60B3F5D6888929178436A0AA23D5176
    /// ControlPort 9051
    /// ```
    ///
    /// In this case, we try:
    ///
    /// ```rust
    /// use tor_control::TorControl;
    /// let mut tc = TorControl::connect("127.0.0.1:9051").unwrap();
    /// tc.auth(Some("\"password\"")).unwrap();
    /// println!("{:?}", tc.getconf(vec!["SOCKSPolicy", "Nickname"]).unwrap());
    /// ```
    ///
    /// Which would print out:
    ///
    /// ```text
    /// ["SocksPolicy=accept 127.0.0.1", "SocksPolicy=reject *", "Nickname"]
    /// ```
    pub fn getconf<P, Ks>(&mut self, kws: Ks) -> TCResult<Vec<String>>
        where P:  AsRef<[u8]>,
              Ks: IntoIterator<Item = P> {
        // Format is:
        // "GETCONF" 1*(SP keyword) CRLF
        try!(self.req_auth());

        // Write the command:
        try_write!(self.stream, b"GETCONF");

        // Write all keywords to get for:
        try!(self.write_many(kws));

        let mut tclock = self.lock_tx();
        try_wend!(tclock.stream);

        // Read all reply lines:
        tclock.read_reply_lines()
    }

    /// Stops all events from being received by sending an empty iterator to
    /// [`setevents0`]. If no events were subscribed to, this is a no op.
    ///
    /// [`setevents0`]: struct.TorControl.html#method.setevents0
    pub fn stopevents(&mut self) -> TCResult<()> {
        if self.asyncs.is_some() {
            self.setevents0(false, iter::empty::<&[u8]>()).and(Ok(()))
        } else {
            Ok(())
        }
    }

    /// Same as [`setevents0`] except that it will panic when no events are
    /// given.
    ///
    /// # Panics
    ///
    /// When the given iterator for `events` yields no elements.
    ///
    /// [`setevents0`]: struct.TorControl.html#method.setevents0
    pub fn setevents<E, Es>(&mut self, extended: bool, events: Es)
        -> TCResult<Receiver<Event>>
        where E:  AsRef<[u8]>,
              Es: IntoIterator<Item = E> {
        self.setevents0(extended, events).map(Option::unwrap)
    }

    /// 3.4. SETEVENTS Request the server to inform the client about interesting
    /// events. See the TorCP documentation for specifics.
    ///
    /// Each event to subscribe to should be an element in the iterator.
    /// A thread is spawned inside the function which handles the async events
    /// and sends them to you by a returned receiver. This thread will run until
    /// you call this again with no events to subscribe to. In that case, no
    /// receiver is returned.
    pub fn setevents0<E, Es>(&mut self, extended: bool, events: Es)
        -> TCResult<Option<Receiver<Event>>>
        where E:  AsRef<[u8]>,
              Es: IntoIterator<Item = E> {
        // Format is:
        // "SETEVENTS" [SP "EXTENDED"] *(SP EventCode) CRLF
        // EventCode = 1*(ALPHA / "_")
        try!(self.req_auth());

        // Write the command:
        try_write!(self.stream, b"SETEVENTS");

        // Extended mode or not?
        if extended {
            try_write!(self.stream, b" EXTENDED");
        }

        // Write all keywords to get for:
        let count = try!(self.write_many(events));

        {
            let mut tclock = self.lock_tx();
            try_wend!(tclock.stream);

            // Are we Ok?
            try!(tclock.read_ok());
        }

        // Destroy sender + old thread:
        if let Some(ref xyz) = self.asyncs {
            xyz.close.store(true, Ordering::Relaxed);
        }
        self.asyncs  = None;

        // If no events are to be subscribed to, we're done.
        if count == 0 {
            return Ok(None);
        }

        // Create receiver, Create & save sender:
        let (tx, rx) = channel();
        let asyncst  = Arc::new(AsyncState {
            evt_tx: Mutex::new(tx),
            close:  AtomicBool::new(false)
        });
        self.asyncs  = Some(asyncst.clone());

        // Spawn thread for async messages:
        std::thread::spawn(move || {
            loop {
                if asyncst.close.load(Ordering::Relaxed) {
                    break;
                }

                //let sender = asyncst.evt_tx.lock().unwrap();
                //let mut buf = String::new();
                //let (status, end, msg) = read_line(&mut self.stream, &mut buf).unwrap();

            }
        });

        Ok(Some(rx))
    }

    /// Gets a configuration as specified in `3.3. GETCONF`.
    ///
    /// Behaves like [`getconf`] except that it takes only one key.
    ///
    /// Also, if the variable is set to its default state, `None` is returned.
    /// If it is not, the value(s) are returned as [`String`]s.
    /// Note that the [`String`]s only include everything after `=`.
    ///
    /// # Examples
    ///
    /// Let's assume that we have `torrc` file that includes, among other things:
    ///
    /// ```text
    /// SOCKSPolicy accept 127.0.0.1
    /// SOCKSPolicy reject *
    /// HashedControlPassword 16:1E4D6C2977B2413E60A8563914D60B3F5D6888929178436A0AA23D5176
    /// ControlPort 9051
    /// ```
    ///
    /// In this case, we try:
    ///
    /// ```
    /// use tor_control::TorControl;
    /// let mut tc = TorControl::connect("127.0.0.1:9051").unwrap();
    /// tc.auth(Some("\"password\"")).unwrap();
    /// println!("{:?}", tc.getconf0("SOCKSPolicy").unwrap());
    /// println!("{:?}", tc.getconf0("Nickname").unwrap());
    /// ```
    ///
    /// Which would print out:
    ///
    /// ```text
    /// Some(["accept 127.0.0.1", "reject *"])
    /// None
    /// ```
    ///
    /// [`getconf`]: struct.TorControl.html#method.getconf
    /// [`String`]: https://doc.rust-lang.org/std/string/struct.String.html
    pub fn getconf0<P>(&mut self, kw: P) -> TCResult<Option<Vec<String>>>
        where P: AsRef<[u8]> {
        // Read variables:
        let lines = try!(self.getconf(iter::once(kw)));

        // Strip everything before = in reply lines, and if it wasn't found,
        // indicate that we found the default value by returning None.
        let mut retr = Vec::with_capacity(lines.len());
        for line in lines {
            match line.rfind('=') {
                None      => return Ok(None),
                Some(idx) => retr.push(line[idx + 1..].into())
            }
        }
        Ok(Some(retr))
    }

    /// Issues a `SAVECONF` command as specified in `3.6. SAVECONF`.
    pub fn saveconf(&mut self) -> TCResult<()> {
        self.authreq_command(b"SAVECONF")
    }

    /// Issues a `NEWNYM` signal as specified in `3.7. SIGNAL`.
    pub fn newnym(&mut self) -> TCResult<()> {
        self.authreq_command(b"SIGNAL NEWNYM")
    }

    /// Issues a `CLEARDNSCACHE` signal as specified in `3.7. SIGNAL`.
    pub fn clear_dns_cache(&mut self) -> TCResult<()> {
        self.authreq_command(b"SIGNAL CLEARDNSCACHE")
    }

    /// Issues a `HEARTBEAT` signal as specified in `3.7. SIGNAL`.
    pub fn heartbeat(&mut self) -> TCResult<()> {
        self.authreq_command(b"SIGNAL HEARTBEAT")
    }

    /// Issues a `RELOAD` signal as specified in `3.7. SIGNAL`.
    pub fn reload(&mut self) -> TCResult<()> {
        // same as: HUP
        self.authreq_command(b"SIGNAL RELOAD")
    }

    /// Issues a `SHUTDOWN` signal as specified in `3.7. SIGNAL`.
    pub fn shutdown(&mut self) -> TCResult<()> {
        // same as: INT
        self.authreq_command(b"SIGNAL SHUTDOWN")
    }

    /// Issues a `HALT` signal as specified in `3.7. SIGNAL`.
    pub fn halt(&mut self) -> TCResult<()> {
        // same as: TERM
        self.authreq_command(b"SIGNAL HALT")
    }

    /// Issues a `DUMP` signal as specified in `3.7. SIGNAL`.
    pub fn dump(&mut self) -> TCResult<()> {
        // same as: USR1
        self.authreq_command(b"SIGNAL DUMP")
    }

    /// Issues a `DEBUG` signal as specified in `3.7. SIGNAL`.
    pub fn debug(&mut self) -> TCResult<()> {
        // same as: USR2
        self.authreq_command(b"SIGNAL DEBUG")
    }
}