#![forbid(unsafe_code)]
#![warn(clippy::nursery, clippy::pedantic)]
#![allow(clippy::missing_panics_doc)]

use client::config::ClientConfig;
use core::net::SocketAddr;
use fhe_core::api::CryptoSystem;
use fhe_exchange::ExchangeData;
use seal_lib::context::SealBFVContext;
use seal_lib::{BfvHOperation, Ciphertext, SealBfvCS};
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

    log::debug!("Client configuration: {:?}", config);

    let mut stream = ensure!(TcpStream::connect(socket_addr).await);

    let bfv_ctx = SealBFVContext::new(
        seal_lib::DegreeType::D4096,
        seal_lib::SecurityLevel::TC128,
        16,
    );
    let bfv_cs = SealBfvCS::new(&bfv_ctx);

    let lhs = 1;
    let rhs = 2;

    let lhs_cipher = bfv_cs.cipher(&lhs);
    let rhs_cipher = bfv_cs.cipher(&rhs);

    let exch_data = ExchangeData::<SealBfvCS>::new(
        vec![lhs_cipher],
        vec![Some(rhs_cipher)],
        vec![BfvHOperation::Add],
    );

    let exch_data_bytes = ensure!(bincode::encode_to_vec(exch_data, BINCODE_CONFIG));

    unsized_data_send(exch_data_bytes, &mut stream).await;

    let results = unsized_data_recv(&mut stream).await;

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
            log::info!("Accepted connection from {}", client_addr);
            server::handle_client(stream).await;
        });
    }
}

async fn unsized_data_send(data: Vec<u8>, stream: &mut TcpStream) {
    let total_size = data.len();
    let total_size_fixed_size = u64::try_from(total_size).unwrap();

    ensure!(stream.write_all(&total_size_fixed_size.to_le_bytes()).await);

    ensure!(stream.write_all(&data).await);
}

async fn unsized_data_recv(stream: &mut TcpStream) -> Vec<u8> {
    let mut size_buf = [0u8; std::mem::size_of::<u64>()];

    ensure!(stream.read_exact(&mut size_buf).await);

    let total_size = usize::from_le_bytes(size_buf);

    let mut buf = vec![0u8; total_size];

    ensure!(stream.read_exact(&mut buf).await);

    buf
}
