use core::net::SocketAddr;
use std::sync::Arc;
use tokio::{net::TcpStream, sync::Mutex};

#[derive(Debug)]
pub enum AuthErrors {}

//TODO scramble key
pub async fn auth_incoming(
    key: Arc<Mutex<[u8; 32]>>,
    trusted_addrs: Arc<Mutex<Vec<SocketAddr>>>,
    incoming_connection: (TcpStream, SocketAddr),
) -> Result<bool, AuthErrors> {

    let key_l = key.lock().await;
    let trusted_addrs_l = trusted_addrs.lock().await;

    
    
    Ok(false)
}
