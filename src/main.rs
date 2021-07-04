use gpg_bridge::SocketType;
use std::os::windows::process::CommandExt;
use std::process::Command;
use std::{env, io};

fn print_help(program: &str) {
    println!("Usage: {} addr-to-bind [path-to-gpg-extra-socket]", program);
    println!();
    println!("Add --detach flag to run it as a background daemon.");
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    pretty_env_logger::init();

    let mut args = env::args();
    let program = args.next().unwrap();

    let mut from = String::new();
    let mut to = None;
    let mut detach = false;
    for arg in args {
        if arg == "--help" || arg == "-h" {
            print_help(&program);
            return Ok(());
        }
        if arg == "--detach" {
            detach = true;
            continue;
        }
        if arg.starts_with('-') || (!from.is_empty() && to.is_some()) {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("unrecoginze arg {}", arg),
            ));
        }
        if from.is_empty() {
            from = arg;
        } else {
            to = Some(arg)
        }
    }
    if from.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "You need to specify bind address",
        ));
    }
    if !detach {
        return gpg_bridge::bridge(SocketType::Extra, from, to).await;
    }

    let _ = gpg_bridge::ping_gpg_agent().await;

    let mut cmd = Command::new(program);
    cmd.arg(from);
    if let Some(t) = to {
        cmd.arg(t);
    }
    cmd.creation_flags(0x0000_0200 | 0x0000_0008 | 0x0400_0000)
        .spawn()?;
    Ok(())
}
