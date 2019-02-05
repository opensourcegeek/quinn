//! API for sending 0-RTT data

use std::mem;

use err_derive::Error;
use futures::channel::oneshot;

use crate::{ConnectionError, IncomingStreams};
use quinn_proto::Directionality;

/// Handle for sending data on an outgoing connection that has not yet been established
pub struct Connection {
    conn: crate::Connection,
    connected: oneshot::Receiver<()>,
}

impl Connection {
    pub(crate) fn new(conn: crate::Connection, connected: oneshot::Receiver<()>) -> Self {
        Self { conn, connected }
    }

    /// Complete the handshake
    pub async fn establish(self) -> Result<(crate::Connection, IncomingStreams), ConnectionError> {
        await!(self.connected).unwrap();
        self.conn.0.check_err()?;
        let incoming = IncomingStreams(self.conn.0.clone());
        incoming.0.inner.lock().unwrap().check_err()?;
        Ok((self.conn, incoming))
    }

    /// Open a new outgoing bidirectional 0-RTT stream
    ///
    /// Note that no data can be received until the handshake completes.
    pub fn open_bi(&self) -> Option<BiStream> {
        let inner = &mut *self.conn.0.inner.lock().unwrap();
        let id = inner.endpoint.open(self.conn.0.ch, Directionality::Bi)?;
        Some(BiStream(crate::BiStream::new(self.conn.0.clone(), id)))
    }

    /// Open a new outgoing unidirectional 0-RTT stream
    pub fn open_uni(&self) -> Option<SendStream> {
        let inner = &mut *self.conn.0.inner.lock().unwrap();
        let id = inner.endpoint.open(self.conn.0.ch, Directionality::Uni)?;
        Some(SendStream(crate::SendStream::new(self.conn.0.clone(), id)))
    }
}

/// 0-RTT bidirectional stream
pub struct BiStream(crate::BiStream);

impl BiStream {
    /// Send `buf` without waiting for the handshake to complete.
    ///
    /// Returns `n < buf.len()` if congestion/flow control block further sending.
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, WriteError> {
        write_0rtt(&mut self.0.send, buf)
    }

    /// Finish the stream without waiting for the handshake to complete.
    pub fn finish(&mut self) -> Result<(), WriteError> {
        finish_0rtt(&mut self.0.send)
    }

    /// Call after the connection is established to attempt conversion into a 1-RTT stream
    ///
    /// Failure indicates that no 0-RTT data was delivered; the application is responsible for
    /// retransmitting if necessary.
    pub fn upgrade(mut self) -> Result<crate::BiStream, UpgradeError> {
        if let Err(e) = upgrade_0rtt(&mut self.0.send) {
            self.0.recv.closed = true;
            return Err(e);
        }
        Ok(self.0)
    }
}

/// 0-RTT unidirectional stream
pub struct SendStream(crate::SendStream);

impl SendStream {
    /// Send `buf` without waiting for the handshake to complete.
    ///
    /// Returns `n < buf.len()` if congestion/flow control block further sending.
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, WriteError> {
        write_0rtt(&mut self.0, buf)
    }

    /// Finish the stream without waiting for the handshake to complete.
    pub fn finish(&mut self) -> Result<(), WriteError> {
        finish_0rtt(&mut self.0)
    }

    /// Call after the connection is established to attempt conversion into a 1-RTT stream
    ///
    /// Failure indicates that no 0-RTT data was delivered; the application is responsible for
    /// retransmitting if necessary.
    pub fn upgrade(mut self) -> Result<crate::SendStream, UpgradeError> {
        upgrade_0rtt(&mut self.0)?; // TODO: Verify that this doesn't send RESET_STREAM on err
        Ok(self.0)
    }
}

/// Errors arising from writing to a 0-RTT stream
#[derive(Debug, Clone, Error)]
pub enum WriteError {
    /// No further data can be written on this stream at least until the handshake completes.
    #[error(display = "blocked by 0-RTT limits")]
    Blocked,
    /// The handshake finished. All further I/O must be performed by converting this stream into
    /// 1-RTT form using its `upgrade` method.
    #[error(display = "cannot perform 0-RTT writes on established connection")]
    Upgrade,
}

/// Errors arising while converting a 0-RTT stream to a 1-RTT stream.
#[derive(Debug, Clone, Error)]
pub enum UpgradeError {
    /// The server rejected all 0-RTT data
    ///
    /// All streams have been returned to their initial empty and unopened state.
    #[error(display = "0-RTT data was rejected")]
    Rejected,
    /// The local application already closed this connection
    #[error(display = "connection closed: {}", _0)]
    ConnectionClosed(ConnectionError),
}

fn write_0rtt(stream: &mut crate::SendStream, buf: &[u8]) -> Result<usize, WriteError> {
    stream.conn.check_err().map_err(|_| WriteError::Upgrade)?;
    let inner = &mut *stream.conn.inner.lock().unwrap();
    if !inner.endpoint.connection(stream.conn.ch).is_handshaking() {
        return Err(WriteError::Upgrade);
    }
    inner.wake();
    use crate::quinn::WriteError::*;
    match inner.endpoint.write(stream.conn.ch, stream.id, buf) {
        Ok(n) => Ok(n),
        Err(Blocked) => Err(WriteError::Blocked),
        Err(Stopped { .. }) => unreachable!(),
    }
}

fn finish_0rtt(stream: &mut crate::SendStream) -> Result<(), WriteError> {
    if mem::replace(&mut stream.finishing, true) {
        return Ok(());
    }
    stream.conn.check_err().map_err(|_| WriteError::Upgrade)?;
    let inner = &mut *stream.conn.inner.lock().unwrap();
    if !inner.endpoint.connection(stream.conn.ch).is_handshaking() {
        return Err(WriteError::Upgrade);
    }
    inner.endpoint.finish(stream.conn.ch, stream.id);
    inner.wake();
    Ok(())
}

fn upgrade_0rtt(stream: &mut crate::SendStream) -> Result<(), UpgradeError> {
    stream
        .conn
        .check_err()
        .map_err(UpgradeError::ConnectionClosed)?;
    let inner = &mut *stream.conn.inner.lock().unwrap();
    if inner.endpoint.connection(stream.conn.ch).accepted_0rtt() {
        Ok(())
    } else {
        stream.closed = true;
        Err(UpgradeError::Rejected)
    }
}
