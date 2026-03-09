use tokio::net::{UdpSocket};
use tokio::time::{sleep, timeout, Duration};
use core::net::SocketAddr;

pub static MAX_BROADCAST_DURATION: u64 = 20;
pub static BROADCAST_NAME: &str = "CesaConn Brodcast";

pub async fn bind_socket(_addr: &str) -> UdpSocket {
    match UdpSocket::bind(_addr).await {
        Ok(s) => {
            println!("Succesfully binded socket.");
            s
        },
        Err(e) => {
            panic!("Failed to bind socket! | Error: {}", e)
        }
    }
}

pub async fn udp_broadcast_presence(_message: &str, _duration: u64) {

    let _duration = if _duration > MAX_BROADCAST_DURATION { MAX_BROADCAST_DURATION } else { _duration };
    let socket = bind_socket("0.0.0.0:6363").await;

    match socket.set_broadcast(true) {
        Ok(_) => println!("Succesfully enabled broadcast mode."),
        Err(e) => eprintln!("Failed to enable broadcast mode! | Error: {}", e),
    };

    for _tick in 0.._duration {

        let message = _message.as_bytes();

        match socket.send_to(message, "255.255.255.255:6363").await {

            Ok(message) => println!("Succesfully broadcasted: {} bytes | Data: {}", message, _message),
            Err(e) => eprintln!("Failed to broadcast presence: {}", e),

        }

        sleep(Duration::from_secs(1)).await;
    };

    match socket.set_broadcast(false) {
        Ok(_) => println!("Succefully disabled broadcast mode."),
        Err(e) => eprintln!("Failed disable broadcast mode! | Error: {}", e),
    };
}

pub async fn udp_find_broadcaster(_duration: u64) -> Option<SocketAddr> {

    let _duration = if _duration > MAX_BROADCAST_DURATION { MAX_BROADCAST_DURATION } else { _duration };

    let socket = bind_socket("0.0.0.0:6363").await;
    let mut buf = [0; 1024];

    println!("Searching for devices on network...");

    let result = timeout(
        Duration::from_secs(_duration),
        socket.recv_from(&mut buf)
    ).await;

    match result {
        Ok(Ok((len, addr))) => {
            if len == buf.len() {
                eprintln!("Too big broadcast data!");
                return None
            }

            let name = String::from_utf8_lossy(&buf[..len]);
            
            if name.starts_with(&BROADCAST_NAME) {
                println!("Found device: {} at IP: {}", name, addr.ip());
                Some(addr)
            } else {
                eprintln!("Found unknown device: {} from {}", name, addr);
                None
            }
        }
        Ok(Err(e)) => {
            eprintln!("Socket error: {}", e);
            None
        }
        Err(_e) => {
            eprintln!("Timeout: Didnt find any device in 5 seconds!");
            None
        }
    }
}
