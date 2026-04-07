use core::net::SocketAddr;
use std::sync::Arc;
use std::fmt;
use tokio::{io::AsyncReadExt, net::TcpStream, sync::Mutex};

#[derive(Debug, PartialEq)]
pub enum AuthErrors {
    FailedToReadFromStream,
}

impl fmt::Display for AuthErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthErrors::FailedToReadFromStream => {
                write!(f, "failed to read authentication key from stream")
            }
        }
    }
}

// TODO: scramble key (constant-time comparison to prevent timing attacks)

/// Authenticates an incoming TCP connection by verifying:
/// 1. The remote address is in the trusted addresses list
/// 2. The first 32 bytes sent match the shared authentication key
pub async fn auth_incoming(
    key: Arc<Mutex<[u8; 32]>>,
    trusted_addrs: Arc<Mutex<Vec<SocketAddr>>>,
    incoming_connection: (&mut TcpStream, SocketAddr),
) -> Result<bool, AuthErrors> {
    let buf = &mut [0u8; 32];

    // Reject connections from addresses not in the trusted list
    if !trusted_addrs.lock().await.contains(&incoming_connection.1) {
        println!(
            "Received connection from untrusted address: {}",
            incoming_connection.1
        );
        return Ok(false);
    }

    println!(
        "Received connection from trusted address: {}",
        incoming_connection.1
    );

    // Read exactly 32 bytes (the full key) from the stream
    incoming_connection
        .0
        .read_exact(buf)
        .await
        .map_err(|_| AuthErrors::FailedToReadFromStream)?;

    // Compare the received key against the expected one
    if buf != key.lock().await.as_ref() {

        zeroize::Zeroize::zeroize(buf); // Clear sensitive data from memory immediately
        
        println!(
            "Authentication failed for address: {}",
            incoming_connection.1
        );
        return Ok(false);
    }

    

    println!(
        "Authentication successful for address: {}",
        incoming_connection.1
    );

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    const TEST_KEY: [u8; 32] = [0xAB; 32];

    /// Helper: spins up a TcpListener, connects a client, returns (server_stream, client_stream, addr)
    async fn setup_tcp_pair() -> (TcpStream, TcpStream, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client = TcpStream::connect(addr).await.unwrap();
        let (server, peer_addr) = listener.accept().await.unwrap();

        (server, client, peer_addr)
    }

    fn make_shared_state(
        key: [u8; 32],
        trusted: Vec<SocketAddr>,
    ) -> (Arc<Mutex<[u8; 32]>>, Arc<Mutex<Vec<SocketAddr>>>) {
        (Arc::new(Mutex::new(key)), Arc::new(Mutex::new(trusted)))
    }

    #[tokio::test]
    async fn test_valid_key_trusted_addr() {
        let (mut server, mut client, peer_addr) = setup_tcp_pair().await;
        let (key, trusted) = make_shared_state(TEST_KEY, vec![peer_addr]);

        // Client sends the correct key
        client.write_all(&TEST_KEY).await.unwrap();

        let result = auth_incoming(key, trusted, (&mut server, peer_addr)).await;
        assert_eq!(result.unwrap(), true);
    }

    #[tokio::test]
    async fn test_wrong_key_trusted_addr() {
        let (mut server, mut client, peer_addr) = setup_tcp_pair().await;
        let (key, trusted) = make_shared_state(TEST_KEY, vec![peer_addr]);

        // Client sends an incorrect key
        client.write_all(&[0x00; 32]).await.unwrap();

        let result = auth_incoming(key, trusted, (&mut server, peer_addr)).await;
        assert_eq!(result.unwrap(), false);
    }

    #[tokio::test]
    async fn test_untrusted_addr() {
        let (mut server, _client, peer_addr) = setup_tcp_pair().await;
        // Trusted list is empty — no address is trusted
        let (key, trusted) = make_shared_state(TEST_KEY, vec![]);

        let result = auth_incoming(key, trusted, (&mut server, peer_addr)).await;
        assert_eq!(result.unwrap(), false);
    }

    #[tokio::test]
    async fn test_incomplete_read_returns_error() {
        let (mut server, mut client, peer_addr) = setup_tcp_pair().await;
        let (key, trusted) = make_shared_state(TEST_KEY, vec![peer_addr]);

        // Client sends only 10 bytes then closes the connection
        client.write_all(&[0xAB; 10]).await.unwrap();
        drop(client);

        let result = auth_incoming(key, trusted, (&mut server, peer_addr)).await;
        assert_eq!(result.unwrap_err(), AuthErrors::FailedToReadFromStream);
    }

    #[test]
    fn test_error_display() {
        let err = AuthErrors::FailedToReadFromStream;
        assert_eq!(
            err.to_string(),
            "failed to read authentication key from stream"
        );
    }
}
