use core::net::{IpAddr, Ipv4Addr};
use std::net::SocketAddr;

use bpce_fhe::{start_client, start_server};
use clap::{Parser, Subcommand};

#[global_allocator]
static GLOBAL_ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Parser)]
#[command(name = "BPCE FHE", version = "0.1.0", about = "FHE utility for BPCE")]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    Client {
        #[arg(short, long, help = "IP address of the server")]
        address: IpAddr,
        #[arg(short, long, default_value_t = 8080, help = "Server port")]
        port: u16,
    },

    Server {
        #[arg(short, long, default_value_t = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), help = "Server port")]
        address: IpAddr,
        #[arg(short, long, default_value_t = 8080, help = "Server port")]
        port: u16,
    },
}

#[tokio::main]
async fn main() {
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
        Mode::Client { address, port } => {
            let socker_addr = SocketAddr::new(address, port);
            log::info!("Starting client.. Connecting to {}.", socker_addr);
            start_client(socker_addr).await;
        }
        Mode::Server { address, port } => {
            let socker_addr = SocketAddr::new(address, port);
            log::info!("Starting server on port {}.", port);
            start_server(socker_addr).await;
        }
    }
}
