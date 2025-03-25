#![forbid(unsafe_code)]
#![warn(clippy::nursery, clippy::pedantic)]
#![allow(clippy::missing_panics_doc)]

use client::config::ClientConfig;
use core::net::SocketAddr;
use fhe_core::api::CryptoSystem;
use load::DataLoader as _;
use seal_lib::context::SealBFVContext;
use seal_lib::{Ciphertext, SealBfvCS};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

mod client;
mod load;
mod server;

const BINCODE_CONFIG: bincode::config::Configuration = bincode::config::standard();

/// On error, log the error and abort the process.
macro_rules! ensure {
    ($expr:expr) => {
        match $expr {
            Ok(val) => val,
            Err(err) => {
                ::log::error!("FATAL: {}", err);
                ::std::process::exit(1);
            }
        }
    };
}

/// On error, log the error and execute the fallback instruction.
macro_rules! faillible {
    ($expr:expr, $fallback:expr) => {
        match $expr {
            Ok(val) => val,
            Err(err) => {
                ::log::error!("{}", err);
                $fallback
            }
        }
    };
}

pub async fn start_client(socket_addr: SocketAddr, config_file: String) {
    let path = PathBuf::from(config_file);
    let config = ensure!(ClientConfig::load_config(&path).await);

    log::debug!("Client configuration: {config:?}");

    let file = ensure!(std::fs::File::open(config.data()));

    let mut stream = ensure!(TcpStream::connect(socket_addr).await);

    let bfv_ctx = SealBFVContext::new(
        seal_lib::DegreeType::D4096,
        seal_lib::SecurityLevel::TC128,
        16,
    );
    let bfv_cs = SealBfvCS::new(&bfv_ctx);

    let exch_data = ensure!(load::csv::CsvLoader::<SealBfvCS>::load(file, &bfv_cs));
    let exch_data_bytes = ensure!(bincode::encode_to_vec(exch_data, BINCODE_CONFIG));

    ensure!(unsized_data_send(exch_data_bytes, &mut stream).await);

    log::debug!("Data sent to server.");
    let start = std::time::Instant::now();

    let results = ensure!(unsized_data_recv(&mut stream).await);

    log::info!("Data received from server in {:?}", start.elapsed());

    let results: (Vec<Ciphertext>, usize) = ensure!(bincode::decode_from_slice_with_context(
        &results,
        BINCODE_CONFIG,
        bfv_ctx
    ));

    let deciphered_results = results
        .0
        .iter()
        .map(|cipher| bfv_cs.decipher(cipher))
        .collect::<Vec<_>>();

    log::info!("Received {:?} from server.", &deciphered_results);
}

pub async fn start_server(socket_addr: SocketAddr) {
    let listener = ensure!(TcpListener::bind(socket_addr).await);

    loop {
        let (stream, client_addr) = faillible!(listener.accept().await, continue);

        tokio::spawn(async move {
            log::info!("Accepted connection from {client_addr}");
            server::handle_client(stream).await;
        });
    }
}

async fn unsized_data_send(data: Vec<u8>, stream: &mut TcpStream) -> Result<(), std::io::Error> {
    let total_size = data.len();

    stream.write_all(&total_size.to_le_bytes()).await?;

    stream.write_all(&data).await?;

    Ok(())
}

async fn unsized_data_recv(stream: &mut TcpStream) -> Result<Vec<u8>, std::io::Error> {
    let mut size_buf = [0u8; std::mem::size_of::<u64>()];

    stream.read_exact(&mut size_buf).await?;

    let total_size = usize::from_le_bytes(size_buf);

    let mut buf = vec![0u8; total_size];

    stream.read_exact(&mut buf).await?;

    Ok(buf)
}
