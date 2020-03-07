use tokio::prelude::*;
use tokio::net::{TcpListener, TcpStream};
use tokio::net::tcp::{ReadHalf, WriteHalf};
use std::fs::File;
use std::{io, ptr, str};
use log::{info, trace, error};

/// A bridge that forwards all requests to certain TCP port
/// to gpg-agent on Windows.
pub struct Bridge {
    from_addr: String,
    to_port: u16,
    nounce: [u8; 16],
}

impl Bridge {
    /// Builds a bridge for TCP:from_addr <--> GPG_SOCKET:to_addr.
    /// 
    /// `to_addr` should point to the path of gnupg UDS.
    pub fn bridge(from_addr: String, to_addr: String) -> io::Result<Bridge> {
        use std::io::Read;

        let mut f = File::open(to_addr)?;
        let mut buffer = Vec::with_capacity(50);
        f.read_to_end(&mut buffer)?;
        if buffer.starts_with(b"!<socket >") {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Cygwin socket is not supported."));
        }
        let (left, right) = buffer.split_at(buffer.len() - 16);
        let to_port: u16 = str::from_utf8(left).unwrap().trim().parse().unwrap();
        let mut nounce = [0; 16];
        unsafe {
            ptr::copy_nonoverlapping(right.as_ptr(), nounce.as_mut_ptr(), 16);
        }
        Ok(Bridge {
            from_addr,
            to_port,
            nounce,
        })
    }

    async fn copy(tag: &str, from: &mut ReadHalf<'_>, to: &mut WriteHalf<'_>) -> io::Result<u64> {
        let mut buf = vec![0; 4096];
        let mut total = 0;
        loop {
            let cnt = from.read(&mut buf).await?;
            if cnt == 0 {
                return Ok(total);
            }
            total += cnt as u64;
            trace!("{} {}", tag, String::from_utf8_lossy(&buf[..cnt]));
            to.write_all(&buf[..cnt]).await?;
        }
    }

    async fn delegate(mut from: TcpStream, to_port: u16, nounce: [u8; 16]) -> io::Result<()> {
        let mut delegate = TcpStream::connect(("127.0.0.1", to_port)).await?;
        delegate.write_all(&nounce).await?;
        delegate.flush().await?;
        
        let (mut source_read, mut source_write) = from.split();
        let (mut target_read, mut target_write) = delegate.split();
        let s2t = Self::copy("-->", &mut source_read, &mut target_write);
        let t2s = Self::copy("<--", &mut target_read, &mut source_write);
        let (s2t_r, t2s_r) = tokio::join!(s2t, t2s);
        info!("connection finished, received {}, reply {}", s2t_r?, t2s_r?);
        Ok(())
    }

    pub async fn serve(self) -> std::result::Result<(), io::Error> {
        let mut listener = TcpListener::bind(&self.from_addr).await?;
        let to_port = self.to_port;
        let nounce = self.nounce;
        loop {
            let (socket, _) = listener.accept().await?;

            tokio::spawn(async move {
                if let Err(e) = Self::delegate(socket, to_port, nounce).await {
                    error!("failed to delegate tcp: {:?}", e);
                }
            }).await?;
        }
    }
}