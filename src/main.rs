use gpg_bridge::Bridge;
use std::{env, io};

#[tokio::main]
async fn main() -> io::Result<()> {
    pretty_env_logger::init();

    let mut args = env::args();
    let program = args.next().unwrap();
    let from = args.next().unwrap_or_else(|| "--help".to_owned());
    if from == "--help" || from == "-h" {
        println!("Usage: {} from-addr [path-to-gpg-extra-socket]", program);
        return Ok(())
    }
    let to = args.next().unwrap_or_else(|| {
        let home = env::var("userprofile").unwrap();
        format!("{}/AppData/Roaming/gnupg/S.gpg-agent.extra", home)
    });
    Bridge::bridge(from, to)?.serve().await
}
