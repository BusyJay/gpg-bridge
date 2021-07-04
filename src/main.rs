use clap::{clap_app, crate_description, crate_version};
use gpg_bridge::SocketType;
use std::os::windows::process::CommandExt;
use std::process::Command;
use std::{env, io};

fn other_error(details: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, details)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    pretty_env_logger::init();

    let matches = clap_app!(("gpg-bridge") =>
        (version: crate_version!())
        (about: crate_description!())
        (@arg SSH: --ssh [ADDRESS] required_unless[EXTRA] +takes_value "Sets the listenning address to bridge the ssh socket")
        (@arg SSH_SOCKET: --("ssh-socket") [PATH] +takes_value "Sets the path to gnupg ssh socket optionally")
        (@arg EXTRA: --extra [ADDRESS] required_unless[SSH] +takes_value "Sets the listenning to bridge the extra socket")
        (@arg EXTRA_SOCKET: --("extra-socket") [PATH] +takes_value "Sets the path to gnupg extra socket optionaly")
        (@arg DETACH: --detach "Runs the program as a background daemon")
    ).get_matches();
    let ssh_bridge = matches.value_of("SSH").map(|addr| {
        let socket = matches.value_of("SSH_SOCKET").map(|s| s.to_string());
        (addr.to_owned(), socket)
    });
    let extra_bridge = matches.value_of("EXTRA").map(|addr| {
        let socket = matches.value_of("EXTRA_SOCKET").map(|s| s.to_string());
        (addr.to_owned(), socket)
    });
    let detach = matches.is_present("DETACH");
    if detach {
        let _ = gpg_bridge::ping_gpg_agent().await;

        let mut args = env::args();
        let mut cmd = Command::new(args.next().unwrap());
        cmd.args(args);
        return cmd
            .creation_flags(0x0000_0200 | 0x0000_0008 | 0x0400_0000)
            .spawn()
            .map(|_| ());
    }

    let ssh_task = async move {
        if let Some((addr, socket)) = ssh_bridge {
            return gpg_bridge::bridge(SocketType::Ssh, addr, socket).await;
        }
        Ok(())
    };
    let extra_task = async move {
        if let Some((addr, socket)) = extra_bridge {
            return gpg_bridge::bridge(SocketType::Extra, addr, socket).await;
        }
        Ok(())
    };
    match tokio::try_join!(ssh_task, extra_task) {
        Ok(_) => Ok(()),
        Err(e) => return Err(other_error(format!("failed to join tasks {:?}", e))),
    }
}
