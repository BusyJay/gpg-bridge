use log::{debug, error, trace};
use std::net::Shutdown;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::{error, io, mem, ptr, str};
use tokio::fs::File;
use tokio::net::tcp::{ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;
use tokio::process::Command;

struct AgentMeta {
    path: Option<String>,
    args: Option<(u16, [u8; 16])>,
}

#[derive(Clone, Copy)]
pub enum SocketType {
    Ssh,
    Extra,
}

impl SocketType {
    fn name(&self) -> &'static str {
        match self {
            SocketType::Ssh => "agent-ssh-socket",
            SocketType::Extra => "agent-extra-socket",
        }
    }
}

async fn load_gpg_socket_path(ty: SocketType) -> io::Result<String> {
    let output = Command::new("gpgconf")
        .arg("--list-dir")
        .arg(ty.name())
        .output()
        .await?;
    if !output.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "failed to load extra socket: {:?}",
                String::from_utf8_lossy(&output.stderr)
            ),
        ));
    }
    Ok(String::from_utf8(output.stdout).unwrap().trim().to_owned())
}

pub async fn ping_gpg_agent() -> io::Result<()> {
    let output = Command::new("gpg-connect-agent")
        .arg("/bye")
        .output()
        .await?;
    if !output.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "failed to start gpg-agent: {:?}",
                String::from_utf8_lossy(&output.stderr)
            ),
        ));
    }
    Ok(())
}

fn report_data_err(e: impl Into<Box<dyn error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

fn load_cygwin_port_nounce(buffer: &[u8]) -> io::Result<(u16, [u8; 16])> {
    // "%u %c %08x-%08x-%08x-%08x\x00"
    let find = |buffer: &[u8], start_pos: usize, delimeter| {
        if buffer.len() <= start_pos {
            return Err(report_data_err("buffer to short"));
        }
        match buffer[start_pos..].iter().position(|c| *c == delimeter) {
            Some(pos) => Ok(pos),
            None => Err(report_data_err("wrong data format")),
        }
    };
    let parse = |buffer: &[u8], radix: u32| match str::from_utf8(buffer) {
        Ok(s) => match u32::from_str_radix(s, radix) {
            Ok(v) => Ok(v),
            Err(e) => Err(report_data_err(e)),
        },
        Err(e) => Err(report_data_err(e)),
    };

    let end_pos = find(&buffer, 0, b' ')?;
    let port = parse(&buffer[..end_pos], 10)?;

    if port < 1
        || port > 65535
        || !buffer[end_pos..].starts_with(b" s ")
        || buffer.len() < end_pos + 3 + 35 + 1
    {
        return Err(report_data_err("wrong data format"));
    }

    let mut start_pos = end_pos + 3;
    let mut nounce = [0u32; 4];
    for pos in 0..4 {
        nounce[pos] = parse(&buffer[start_pos..start_pos + 4], 16)?;
        if pos < 3 {
            if buffer[start_pos + 4] != b'-' {
                return Err(report_data_err("wrong data format"));
            }
        } else if buffer[start_pos + 4] != b'x' {
            return Err(report_data_err("wrong data format"));
        }
        start_pos += 5;
    }
    // It's on purpose to ignore endianess.
    Ok((port as u16, unsafe { mem::transmute(nounce) }))
}

async fn load_port_nounce(path: &str) -> io::Result<(u16, [u8; 16])> {
    if !Path::new(&path).exists() {
        ping_gpg_agent().await?;
    }
    let mut f = File::open(&path.replace("\\", "/")).await?;
    let mut buffer = Vec::with_capacity(50);
    f.read_to_end(&mut buffer).await?;
    if buffer.starts_with(b"!<socket >") {
        return load_cygwin_port_nounce(&buffer[10..]);
    }
    let (left, right) = buffer.split_at(buffer.len() - 16);
    let to_port: u16 = str::from_utf8(left).unwrap().trim().parse().unwrap();
    let mut nounce = [0; 16];
    unsafe {
        ptr::copy_nonoverlapping(right.as_ptr(), nounce.as_mut_ptr(), 16);
    }
    Ok((to_port, nounce))
}

async fn copy(tag: &str, from: &mut ReadHalf<'_>, to: &mut WriteHalf<'_>) -> io::Result<u64> {
    let mut buf = vec![0; 4096];
    let mut total = 0;
    loop {
        let cnt = from.read(&mut buf).await?;
        if cnt == 0 {
            to.as_ref().shutdown(Shutdown::Write)?;
            return Ok(total);
        }
        total += cnt as u64;
        trace!("{} {}", tag, String::from_utf8_lossy(&buf[..cnt]));
        to.write_all(&buf[..cnt]).await?;
    }
}

async fn delegate(mut from: TcpStream, to_port: u16, nounce: [u8; 16]) -> io::Result<()> {
    let mut delegate = match TcpStream::connect(("127.0.0.1", to_port)).await {
        Ok(s) => s,
        Err(e) => {
            // It's possible that gpg-client was killed and leave stale meta untouched.
            // Reping agent to make it startup.
            let _ = ping_gpg_agent().await;
            return Err(e);
        }
    };
    delegate.write_all(&nounce).await?;
    delegate.flush().await?;

    let (mut source_read, mut source_write) = from.split();
    let (mut target_read, mut target_write) = delegate.split();
    let s2t = copy("-->", &mut source_read, &mut target_write);
    let t2s = copy("<--", &mut target_read, &mut source_write);
    let (received, replied) = tokio::join!(s2t, t2s);
    debug!(
        "connection finished, received {}, replied {}",
        received?, replied?
    );
    Ok(())
}

/// A bridge that forwards all requests from certain TCP port to gpg-agent on Windows.
///
/// `to_path` should point to the path of gnupg UDS.
pub async fn bridge(ty: SocketType, from_addr: String, to_path: Option<String>) -> io::Result<()> {
    // Attempt to setup gpg-agent if it's not up yet.
    let _ = ping_gpg_agent().await;
    let mut listener = TcpListener::bind(&from_addr).await?;

    let meta = Arc::new(Mutex::new(AgentMeta {
        path: to_path,
        args: None,
    }));
    loop {
        let (socket, _) = listener.accept().await?;

        let meta = meta.clone();
        let (port, nounce) = {
            let mut m = meta.lock().unwrap();
            if m.args.is_none() {
                if m.path.is_none() {
                    m.path = Some(load_gpg_socket_path(ty).await?);
                }
                m.args = Some(load_port_nounce(m.path.as_ref().unwrap()).await?);
            }
            m.args.unwrap()
        };

        tokio::spawn(async move {
            if let Err(e) = delegate(socket, port, nounce).await {
                error!("failed to delegate tcp: {:?}", e);
                meta.lock().unwrap().args.take();
            }
        });
    }
}
