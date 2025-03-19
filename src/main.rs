use clap::{Parser, Subcommand};
use std::str::FromStr;

#[derive(Parser)]
#[command(name = "BPCE FHE", version = "0.1.0", about = "FHE utility for BPCE")]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    Client {
        #[arg(short, long, help = "IP address and port of the server")]
        address: String,
    },

    Server {
        #[arg(short, long, default_value_t = 8080, help = "Server port")]
        port: u16,
    },
}

fn main() {
    pretty_env_logger::formatted_builder()
        .filter_level(
            #[cfg(debug_assertions)]
            log::LevelFilter::Debug,
            #[cfg(not(debug_assertions))]
            log::LevelFilter::Info,
        )
        .init();

    let cli = Cli::parse();

    match cli.mode {
        Mode::Client { address } => {
            let socket_addr = core::net::SocketAddr::from_str(&address).expect("Invalid address");
            log::info!("Starting client.. Connecting to {}.", socket_addr);
        }
        Mode::Server { port } => {
            log::info!("Starting serveur on port {}.", port);
        }
    }
}
