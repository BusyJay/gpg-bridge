use clap::Parser;
use gpg_bridge::other_error;
use gpg_bridge::SocketType;
use std::os::windows::process::CommandExt;
use std::process::Command;
use std::{env, io};

#[derive(Parser)]
#[command(name = "gpg-bridge")]
#[command(version, about)]
struct GpgBridge {
    /// Sets the listenning address to bridge the ssh socket
    #[arg(long, value_name("ADDRESS"), required_unless_present("extra"))]
    ssh: Option<String>,
    /// Sets the listenning to bridge the extra socket
    #[arg(long, value_name("ADDRESS"), required_unless_present("ssh"))]
    extra: Option<String>,
    /// Sets the path to gnupg extra socket optionaly
    #[arg(long, value_name("PATH"))]
    extra_socket: Option<String>,
    /// Runs the program as a background daemon
    #[arg(long)]
    detach: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    pretty_env_logger::init();
    let cfg = GpgBridge::parse();
    if cfg.detach {
        let _ = gpg_bridge::ping_gpg_agent().await;

        let mut args = env::args();
        let mut cmd = Command::new(args.next().unwrap());
        for arg in args {
            if arg != "--detach" {
                cmd.arg(arg);
            }
        }
        return cmd
            .creation_flags(0x0000_0200 | 0x0000_0008 | 0x0400_0000)
            .spawn()
            .map(|_| ());
    }

    let ssh_from = cfg.ssh;
    let ssh_task = async move {
        if let Some(from_addr) = ssh_from {
            return gpg_bridge::bridge(SocketType::Ssh, from_addr, None).await;
        }
        Ok(())
    };
    let (extra_from, extra_to) = (cfg.extra, cfg.extra_socket);
    let extra_task = async move {
        if let Some(from_addr) = extra_from {
            return gpg_bridge::bridge(SocketType::Extra, from_addr, extra_to).await;
        }
        Ok(())
    };
    match tokio::try_join!(ssh_task, extra_task) {
        Ok(_) => Ok(()),
        Err(e) => return Err(other_error(format!("failed to join tasks {:?}", e))),
    }
}
