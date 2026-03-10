use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{sleep, timeout, Duration};

const DEFAULT_ADDR: &str = "127.0.0.1:8080";
const INIT_BUFFER_SIZE: usize = 1024;

async fn recv() {

    let listener = TcpListener::bind(&DEFAULT_ADDR);

}