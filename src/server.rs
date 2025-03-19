use tokio::{io::AsyncReadExt, net::TcpStream};

pub async fn handle_client(mut stream: TcpStream) {
    let mut buf = [0; 1024];

    let bytes_read = stream
        .read(&mut buf)
        .await
        .expect("Failed to read data from client");

    log::info!(
        "Received data from client: {:?}",
        String::from_utf8_lossy(&buf[..bytes_read])
    );
}
