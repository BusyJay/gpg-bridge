use std::{
    io, mem,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{ready, Future};
use log::trace;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{
        windows::named_pipe::{NamedPipeServer, ServerOptions},
        TcpListener, TcpStream,
    },
};

pub fn other_error(details: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, details)
}

pub type PinAsyncRead<'a> = Pin<Box<dyn AsyncRead + Send + 'a>>;
pub type PinAsyncWrite<'a> = Pin<Box<dyn AsyncWrite + Send + 'a>>;

pub trait SplitStream {
    fn split_rw(&mut self) -> (PinAsyncRead, PinAsyncWrite);
}

impl SplitStream for TcpStream {
    #[inline]
    fn split_rw(&mut self) -> (PinAsyncRead, PinAsyncWrite) {
        let (read_half, write_half) = TcpStream::split(self);
        (Box::pin(read_half), Box::pin(write_half))
    }
}

struct PipeServerRead<'a> {
    server: &'a NamedPipeServer,
}

impl<'a> AsyncRead for PipeServerRead<'a> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        trace!("polling pipe reader");
        if let Err(e) = ready!(self.server.poll_read_ready(cx)) {
            return Poll::Ready(Err(e));
        }
        loop {
            let arr = buf.initialize_unfilled();
            match self.server.try_read(arr) {
                Ok(n) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if let Err(e) = ready!(self.server.poll_read_ready(cx)) {
                        return Poll::Ready(Err(e));
                    }
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }
}

struct PipeServerWrite<'a> {
    server: &'a NamedPipeServer,
}

impl<'a> AsyncWrite for PipeServerWrite<'a> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        trace!("polling pipe writer");
        if let Err(e) = ready!(self.server.poll_write_ready(cx)) {
            return Poll::Ready(Err(e));
        }
        loop {
            match self.server.try_write(buf) {
                Ok(n) => return Poll::Ready(Ok(n)),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if let Err(e) = ready!(self.server.poll_read_ready(cx)) {
                        return Poll::Ready(Err(e));
                    }
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        trace!("polling pipe flush");
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        trace!("polling pipe shutdown");
        self.poll_flush(cx)
    }
}

impl SplitStream for NamedPipeServer {
    fn split_rw(&mut self) -> (PinAsyncRead, PinAsyncWrite) {
        (
            Box::pin(PipeServerRead { server: self }),
            Box::pin(PipeServerWrite { server: self }),
        )
    }
}

pub trait Listener {
    type Connection;
    fn accept<'a>(&'a mut self)
        -> Pin<Box<dyn Future<Output = io::Result<Self::Connection>> + 'a>>;
}

impl Listener for TcpListener {
    type Connection = TcpStream;
    fn accept<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::Connection>> + 'a>> {
        Box::pin(async move {
            let (conn, _) = TcpListener::accept(self).await?;
            Ok(conn)
        })
    }
}

pub struct NamedPipeServerListener {
    server: NamedPipeServer,
    addr: String,
}

impl NamedPipeServerListener {
    pub fn new(server: NamedPipeServer, addr: String) -> NamedPipeServerListener {
        NamedPipeServerListener { server, addr }
    }
}

impl Listener for NamedPipeServerListener {
    type Connection = NamedPipeServer;
    fn accept<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::Connection>> + 'a>> {
        Box::pin(async move {
            self.server.connect().await?;
            let server = ServerOptions::new().create(&self.addr)?;
            Ok(mem::replace(&mut self.server, server))
        })
    }
}
