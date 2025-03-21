#![forbid(unsafe_code)]
#![warn(clippy::nursery, clippy::pedantic)]
#![allow(clippy::missing_panics_doc)]

use client::config::ClientConfig;
use core::net::SocketAddr;
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

mod client;
mod load;
mod server;

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
    let _config = ensure!(ClientConfig::load_config(&path).await);

    let mut stream = ensure!(TcpStream::connect(socket_addr).await);

    ensure!(stream.write_all(b"Hello, world!").await);
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
