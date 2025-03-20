#![forbid(unsafe_code)]
#![warn(clippy::nursery, clippy::pedantic)]
#![allow(clippy::missing_panics_doc)]

use core::net::SocketAddr;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

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

pub async fn start_client(socket_addr: SocketAddr) {
    let mut stream = ensure!(TcpStream::connect(socket_addr).await);

    ensure!(stream.write_all(b"Hello, world!").await);
}

pub async fn start_server(port: u16) {
    let socket_addr = SocketAddr::new([0, 0, 0, 0].into(), port);
    let listener = ensure!(TcpListener::bind(socket_addr).await);

    loop {
        let (stream, client_addr) = faillible!(listener.accept().await, continue);

        tokio::spawn(async move {
            log::info!("Accepted connection from {}", client_addr);
            server::handle_client(stream).await;
        });
    }
}
