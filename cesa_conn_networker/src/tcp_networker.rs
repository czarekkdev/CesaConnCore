use tokio::net::{TcpListener, TcpStream};
use core::net::{SocketAddr};

pub static DEFAULT_ADDR: &str = "127.0.0.1:6969";
pub static AUTH_BUFFER_SIZE: usize = 1024;
pub static BUFFER_SIZE: usize = 4096;

/// Binds a TCP socket to the given address and returns it.
/// Panics if binding fails — intentional, as the app cannot function without a socket.
pub async fn bind_socket(addr: &str) -> TcpListener {
    match TcpListener::bind(addr).await {
        Ok(s) => {
            println!("Succesfully binded socket.");
            s
        },
        Err(e) => {
            panic!("Failed to bind socket! | Error: {}", e)
        }
    }
}

// TODO : Auth
pub async fn recv_handler(connection: (TcpStream, SocketAddr)) {

    //logic here
}

// TODO : Auth
pub async fn connect_handler(connection: (TcpStream, SocketAddr)) {

    //logic here
}


pub async fn recv(addr: &str) {

    let listener = bind_socket(addr).await;

    println!("Listening on: {addr}");

    loop {

        match listener.accept().await {

            Ok(connection) => {
                println!("Successfully accepted connection.");

                tokio::spawn(async move {recv_handler(connection).await});
            },
            Err(_) => {
                eprintln!("Failed to accept connection!");
            }

        };

    }
}

pub async fn connect(addr: &str) {
    match TcpStream::connect(addr).await {
        Ok(s) => {
            let addr: SocketAddr = addr.parse().unwrap();
            let connection = (s, addr);

            tokio::spawn(async move {connect_handler(connection).await});
        },

        Err(_) => {
            eprintln!("Failed to connect!");
        }
    };
}