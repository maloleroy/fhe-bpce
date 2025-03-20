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
        #[arg(short, long, help = "IP address and port of the server")]
        address: core::net::SocketAddr,
    },

    Server {
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
        Mode::Client { address } => {
            log::info!("Starting client.. Connecting to {}.", address);
            start_client(address).await;
        }
        Mode::Server { port } => {
            log::info!("Starting serveur on port {}.", port);
            start_server(port).await;
        }
    }
}
