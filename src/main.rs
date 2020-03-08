use std::{env, io};

#[tokio::main]
async fn main() -> io::Result<()> {
    pretty_env_logger::init();

    let mut args = env::args();
    let program = args.next().unwrap();
    let from = args.next().unwrap_or_else(|| "--help".to_owned());
    if from == "--help" || from == "-h" {
        println!("Usage: {} from-addr [path-to-gpg-extra-socket]", program);
        return Ok(());
    }
    let to = args.next();
    gpg_bridge::bridge(from, to).await
}
