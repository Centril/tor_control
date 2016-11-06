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

// Standard Library:
use std::iter;

use std::str;
use std::io::{self, Write, BufWriter, Read, BufRead, BufReader};
use std::net::{TcpStream, ToSocketAddrs};

use std::sync::mpsc::{self, channel, Receiver, Sender};

use std::convert::{TryFrom, TryInto};
use std::fmt::{self, Display, Debug, Formatter};
use std::error::Error;

// BufStream:
extern crate bufstream;
use bufstream::BufStream;

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
    SendError(mpsc::SendError<(u32, bool, String)>),
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
            SendError(ref e)    => e.description(),
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

impl From<mpsc::SendError<(u32, bool, String)>> for TCError {
    fn from(err: mpsc::SendError<(u32, bool, String)>) -> TCError {
        SendError(err)
    }
}

//============================================================================//
// Internal / Reading utilities                                               //
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

/// Writes an iterator of byte arrays to the stream, separated by whitespace.
fn write_many<W, I, Is>(writer: &mut W, items: Is) -> TCResult<usize>
where W:  Write,
      I:  AsRef<[u8]>,
      Is: IntoIterator<Item = I> {
    let mut c = 0;
    for item in items.into_iter() {
        try_write!(writer, b" ", item.as_ref());
        c += 1;
    }
    Ok(c)
}

//============================================================================//
// Internal / Reading utilities                                               //
//============================================================================//

/// Converts a "string" to a u32, or fails with `UnknownResponse`.
fn str_to_u32<S: AsRef<str>>(s: S) -> TCResult<u32> {
    s.as_ref().parse().map_err(|_| TCError::UnknownResponse)
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

fn read_line<'b, R: BufRead>(stream: &mut R, buf: &'b mut String)
    -> TCResult<(u32, bool, &'b str)> {
    // Read a line and make sure we have at least 3 (status) + 1 (sep) bytes.
    if try!(stream.read_line(buf)) < 4 {
        return Err(UnknownResponse)
    }
    let (buf_s, msg) = buf.split_at(4);
    let status       = try!(read_status(&buf_s));
    let is_end       = try!(read_is_end(&buf_s));
    Ok((status, is_end, msg))
}

/// Handles a status code, 250 or 251 is Ok, otherwise error.
fn handle_code(status: u32) -> TCResult<()> {
    match status {
        250 | 251 => Ok(()),
        status    => Err(status.into())
    }
}

/// Reads a status code, if `250` -> `Ok(())`, otherwise -> error.
fn read_ok_sync<R: BufRead>(read: &mut R) -> TCResult<()> {
    let mut buf = String::new();
    let (status, end, _) = try!(read_line(read, &mut buf));
    if end {
        handle_code(status)
    } else {
        Err(UnknownResponse)
    }
}

/// Reads one or many reply lines as specified in `2.3`.
/// Terminates early on status code other than `250`.
fn read_lines_sync<R: BufRead>(read: &mut R) -> TCResult<Vec<String>> {
    let mut rls: Vec<String> = Vec::with_capacity(1);
    let mut buf = String::new();
    loop {
        {
            let (status, end, msg) = try!(read_line(read, &mut buf));
            try!(handle_code(status));
            rls.push(msg.trim_right().to_owned());
            if end {
                break;
            }
        }
        buf.clear();
    }

    Ok(rls)
}

//============================================================================//
// Traits needed for backends:                                                //
//============================================================================//

pub trait TryClone where Self: Sized {
    fn try_clone(&self) -> io::Result<Self>;
}

//============================================================================//
// API Traits:                                                                //
//============================================================================//

pub trait Connectable where Self: Sized {
    type Error;
    fn connect<A: ToSocketAddrs>(addr: A) -> Result<Self, Self::Error>;
}

pub trait IsAuth {
    /// Returns true if we are authenticated.
    fn is_auth(&self) -> bool;
}

pub trait IsAsync {
    /// Returns true if we are in async mode.
    fn is_async(&self) -> bool;
}

pub trait TorLimited {

}

pub trait TorControl {
    type Writer: Write;

    #[doc(hidden)]
    fn writer(&mut self) -> &mut Self::Writer;

    #[doc(hidden)]
    fn read_ok(&mut self) -> TCResult<()>;

    #[doc(hidden)]
    /// Reads one or many reply lines as specified in `2.3`.
    /// Terminates early on status code other than `250`.
    fn read_lines(&mut self) -> TCResult<Vec<String>>;

    #[doc(hidden)]
    /// Executes a simple "one-shot" command expecting a 250 OK reply back.
    fn command<P>(&mut self, cmd: P) -> TCResult<()>
    where P: AsRef<[u8]> {
        try_wend!(self.writer(), cmd.as_ref());
        self.read_ok()
    }

    #[doc(hidden)]
    /// Used for `setconf` and `resetconf`.
    fn xsetconf<K, V>(&mut self, cmd: &[u8], kw: K, val: Option<V>)
       -> TCResult<()>
    where K: AsRef<[u8]>,
          V: AsRef<[u8]> {
        {
            let mut writer = self.writer();
            try_wend!(writer, cmd.as_ref(), b" ", kw.as_ref());
            if let Some(value) = val {
                try_write!(writer, b" = ", value.as_ref());
            }
            try_wend!(writer);
        }

        self.read_ok()
    }

    /// Sets a configuration as specified in `3.1. SETCONF`.
    ///
    /// It sets the configuration variable specified by `kw` to `value`
    /// when `val == Some(value)` is given. Otherwise, on `None`,
    /// it is reset to `0` or `NULL`.
    fn setconf<K, V>(&mut self, kw: K, val: Option<V>) -> TCResult<()>
    where K: AsRef<[u8]>,
          V: AsRef<[u8]> {
        self.xsetconf(b"SETCONF", kw, val)
    }

    /// Sets a configuration as specified in `3.2. RESETCONF`.
    ///
    /// Behaves as [`setconf`] in every respect except for what happens when
    /// `val == None`. In that case, the configuration variable specified by
    /// `kw` is reset to the default value.
    ///
    /// [`setconf`]: struct.TorControl.html#method.setconf
    fn resetconf<K, V>(&mut self, kw: K, val: Option<V>) -> TCResult<()>
    where K: AsRef<[u8]>,
          V: AsRef<[u8]> {
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
    fn getconf<P, Ks>(&mut self, kws: Ks) -> TCResult<Vec<String>>
    where P:  AsRef<[u8]>,
          Ks: IntoIterator<Item = P> {
        {
            // Format is:
            // "GETCONF" 1*(SP keyword) CRLF
            // Write the command:
            let mut writer = self.writer();
            try_write!(writer, b"GETCONF");

            // Write all keywords to get for:
            try!(write_many(&mut writer, kws));
            try_wend!(writer);
        }

        self.read_lines()
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
    fn getconf0<K>(&mut self, kw: K) -> TCResult<Option<Vec<String>>>
    where K: AsRef<[u8]> {
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
    fn saveconf(&mut self) -> TCResult<()> {
        self.command(b"SAVECONF")
    }

    /// Issues a `NEWNYM` signal as specified in `3.7. SIGNAL`.
    fn newnym(&mut self) -> TCResult<()> {
        self.command(b"SIGNAL NEWNYM")
    }

    /// Issues a `CLEARDNSCACHE` signal as specified in `3.7. SIGNAL`.
    fn clear_dns_cache(&mut self) -> TCResult<()> {
        self.command(b"SIGNAL CLEARDNSCACHE")
    }

    /// Issues a `HEARTBEAT` signal as specified in `3.7. SIGNAL`.
    fn heartbeat(&mut self) -> TCResult<()> {
        self.command(b"SIGNAL HEARTBEAT")
    }

    /// Issues a `RELOAD` signal as specified in `3.7. SIGNAL`.
    fn reload(&mut self) -> TCResult<()> {
        // same as: HUP
        self.command(b"SIGNAL RELOAD")
    }

    /// Issues a `SHUTDOWN` signal as specified in `3.7. SIGNAL`.
    fn shutdown(&mut self) -> TCResult<()> {
        // same as: INT
        self.command(b"SIGNAL SHUTDOWN")
    }

    /// Issues a `HALT` signal as specified in `3.7. SIGNAL`.
    fn halt(&mut self) -> TCResult<()> {
        // same as: TERM
        self.command(b"SIGNAL HALT")
    }

    /// Issues a `DUMP` signal as specified in `3.7. SIGNAL`.
    fn dump(&mut self) -> TCResult<()> {
        // same as: USR1
        self.command(b"SIGNAL DUMP")
    }

    /// Issues a `DEBUG` signal as specified in `3.7. SIGNAL`.
    fn debug(&mut self) -> TCResult<()> {
        // same as: USR2
        self.command(b"SIGNAL DEBUG")
    }
}

//============================================================================//
// TcpStream implementation:                                                  //
//============================================================================//

impl Connectable for TcpStream {
    type Error = io::Error;
    fn connect<A: ToSocketAddrs>(addr: A) -> Result<Self, Self::Error> {
        Self::connect(addr)
    }
}

impl TryClone for TcpStream {
    fn try_clone(&self) -> io::Result<Self> {
        self.try_clone()
    }
}

//============================================================================//
// TCNoAuth                                                                   //
//============================================================================//

pub struct TCNoAuth<T: Read + Write>(BufStream<T>);

impl<T: Read + Write> IsAuth for TCNoAuth<T> {
    fn is_auth(&self) -> bool {
        false
    }
}

impl<T: Read + Write> IsAsync for TCNoAuth<T> {
    fn is_async(&self) -> bool {
        false
    }
}

impl<T> Connectable for TCNoAuth<T>
where T: Connectable<Error = io::Error> + Read + Write {
    type Error = TCError;
    fn connect<A: ToSocketAddrs>(addr: A) -> Result<Self, Self::Error> {
        Ok(TCNoAuth::new(try!(T::connect(addr))))
    }
}

impl<T: Read + Write> TCNoAuth<T> {
    /// Constructs an interface to TorCP given the backing stream of type `T`,
    /// which is most often a `TcpStream`.
    pub fn new(stream: T) -> Self {
        TCNoAuth(BufStream::new(stream))
    }

    /// Authenticates to TorCP as specified in `3.5. AUTHENTICATE`.
    ///
    /// If no password is required, `mpass == None`, otherwise `Some("<pass>")`.
    pub fn auth<P>(self, mpass: Option<P>) -> TCResult<TCAuth<T>>
    where P: AsRef<[u8]> {
        let mut stream = self.0;

        if let Some(pass) = mpass {
            try_wend!(stream, b"AUTHENTICATE ", pass.as_ref());
        } else {
            try_wend!(stream, b"AUTHENTICATE");
        }

        try!(read_ok_sync(&mut stream));

        Ok(TCAuth(stream))
    }
}

//============================================================================//
// TCAuth:                                                                    //
//============================================================================//

pub struct TCAuth<T: Read + Write>(BufStream<T>);

impl<T: Read + Write> IsAuth for TCAuth<T> {
    fn is_auth(&self) -> bool {
        true
    }
}

impl<T: Read + Write> IsAsync for TCAuth<T> {
    fn is_async(&self) -> bool {
        false
    }
}

impl<T: Read + Write> TorControl for TCAuth<T> {
    type Writer = BufStream<T>;

    fn writer(&mut self) -> &mut Self::Writer {
        &mut self.0
    }

    fn read_ok(&mut self) -> TCResult<()> {
        read_ok_sync(&mut self.0)
    }

    /// Reads one or many reply lines as specified in `2.3`.
    /// Terminates early on status code other than `250`.
    fn read_lines(&mut self) -> TCResult<Vec<String>> {
        read_lines_sync(&mut self.0)
    }
}

//============================================================================//
// SETEVENTS, 3.4                                                             //
//============================================================================//

pub type Event = String;

pub struct Poll<T: Read + Write> {
    reader:  BufReader<T>,
    sync_tx: Sender<(u32, bool, String)>
}

impl<T: Read + Write + TryClone + Debug> TCAuth<T> {
    /// 3.4. SETEVENTS Request the server to inform the client about interesting
    /// events. See the TorCP documentation for specifics.
    ///
    /// Each event to subscribe to should be an element in the iterator.
    /// A thread is spawned inside the function which handles the async events
    /// and sends them to you by a returned receiver. This thread will run until
    /// you call this again with no events to subscribe to. In that case, no
    /// receiver is returned.
    pub fn setevents<E, Es>(self, extended: bool, events: Es) -> TCResult<(TCAsync<T>, Poll<T>)>
    where E:  AsRef<[u8]>,
          Es: IntoIterator<Item = E> {
        // Format is:
        // "SETEVENTS" [SP "EXTENDED"] *(SP EventCode) CRLF
        // EventCode = 1*(ALPHA / "_")
        let mut stream = self.0;

        // Write the command:
        try_write!(stream, b"SETEVENTS");

        // Extended mode or not?
        if extended {
            try_write!(stream, b" EXTENDED");
        }

        // Subscribe to all events & check if we're OK:
        try!(write_many(&mut stream, events));
        try_wend!(stream);
        try!(read_ok_sync(&mut stream));

        // Since we already flushed out the data, this should never happen:
        let reader = stream.into_inner().unwrap();
        let writer = try!(reader.try_clone());

        // Channel for communication between Async & Sync:
        let (sync_tx, sync_rx) = channel();
        Ok((
            TCAsync {
                writer:  BufWriter::new(writer),
                sync_rx: sync_rx
            },
            Poll {
                reader:  BufReader::new(reader),
                sync_tx: sync_tx
            }
        ))
    }
}

impl<T: Read + Write> Poll<T> {
    pub fn poll(&mut self) -> TCResult<Option<String>> {
        let mut buf = String::new();
        let (status, end, msg) = try!(read_line(&mut self.reader, &mut buf));

        if status == 650 {
            Ok(Some(msg.to_owned()))
        } else {
            try!(self.sync_tx.send((status, end, msg.to_owned())));
            Ok(None)
        }
    }
}

impl<T: Read + Write + Debug> TCAsync<T> {
    pub fn stopevents(mut self) -> TCResult<TCAuth<T>> {
        try_wend!(self.writer(), b"SETEVENTS");
        try!(self.read_ok());

        let w = self.writer.into_inner().unwrap();

        Ok(TCAuth(BufStream::new(w)))
    }
}

//============================================================================//
// TCAsync:                                                                   //
//============================================================================//

pub struct TCAsync<T: Read + Write> {
    writer:  BufWriter<T>,
    sync_rx: Receiver<(u32, bool, String)>
}

impl<T: Read + Write> IsAuth for TCAsync<T> {
    fn is_auth(&self) -> bool {
        true
    }
}

impl<T: Read + Write> IsAsync for TCAsync<T> {
    fn is_async(&self) -> bool {
        true
    }
}

impl<T: Read + Write> TorControl for TCAsync<T> {
    type Writer = BufWriter<T>;

    fn writer(&mut self) -> &mut Self::Writer {
        &mut self.writer
    }

    fn read_ok(&mut self) -> TCResult<()> {
        let (status, end, _) = self.sync_rx.recv().unwrap();
        try!(handle_code(status));
        if end {
            Ok(())
        } else {
            Err(UnknownResponse)
        }
    }

    /// Reads one or many reply lines as specified in `2.3`.
    /// Terminates early on status code other than `250`.
    fn read_lines(&mut self) -> TCResult<Vec<String>> {
        let mut rls: Vec<String> = Vec::with_capacity(1);
        loop {
            let (status, end, msg) = self.sync_rx.recv().unwrap();
            try!(handle_code(status));
            rls.push(msg.trim_right().to_owned());
            if end {
                break;
            }
        }
        Ok(rls)
    }
}