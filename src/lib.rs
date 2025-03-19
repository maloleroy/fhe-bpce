#![forbid(unsafe_code)]
#![warn(clippy::nursery, clippy::pedantic)]
#![allow(clippy::missing_panics_doc)]

use core::net::SocketAddr;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

mod server;

pub async fn start_client(socket_addr: SocketAddr) {
    let mut stream = TcpStream::connect(socket_addr)
        .await
        .expect("Failed to connect to server");

    stream
        .write_all(b"Hello, world!")
        .await
        .expect("Failed to send data to server");
}

pub async fn start_server(port: u16) {
    let socket_addr = SocketAddr::new([0, 0, 0, 0].into(), port);
    let listener = TcpListener::bind(socket_addr)
        .await
        .expect("Failed to bind to port");

    loop {
        let (stream, client_addr) = listener
            .accept()
            .await
            .expect("Failed to accept connection");

        tokio::spawn(async move {
            log::info!("Accepted connection from {}", client_addr);
            server::handle_client(stream).await;
        });
    }
}
