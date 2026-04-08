use cesa_conn_crypto::aes::decrypt;
use cesa_conn_crypto::ecdh::{
    calculate_public_key, calculate_shared_key, generate_private_key, hash_key,
};
use core::net::SocketAddr;
use std::fmt;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::{io::AsyncReadExt, net::TcpStream, sync::RwLock};
use zeroize::Zeroize;

/// All errors that can occur during authentication.
#[derive(Debug, PartialEq)]
pub enum AuthErrors {
    /// The TCP stream ended or errored before we could read all expected bytes.
    FailedToReadFromStream,
    /// AES-GCM decryption failed — wrong shared secret or tampered data.
    FailedToDecrypt,
    /// The TCP stream errored while sending data to the client.
    FailedToWriteToStream,
}

impl fmt::Display for AuthErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthErrors::FailedToReadFromStream => {
                write!(f, "failed to read authentication key from stream")
            }
            AuthErrors::FailedToDecrypt => write!(f, "failed to decrypt authentication key"),
            AuthErrors::FailedToWriteToStream => write!(f, "failed to write to stream"),
        }
    }
}

// TODO: use constant-time comparison (e.g. subtle::ConstantTimeEq) to prevent timing attacks

/// Authenticates an incoming TCP connection using ECDH key exchange + pre-shared key verification.
///
/// Handshake sequence:
///   1. Client → Server: client's X25519 ephemeral public key (32 bytes)
///   2. Server → Client: server's X25519 ephemeral public key (32 bytes)
///   3. Client → Server: nonce (12 bytes) + AES-256-GCM ciphertext (48 bytes) = 60 bytes
///      - Client encrypts the pre-shared key using SHA-256(ECDH shared secret) as the AES key
///   4. Server decrypts and compares against the known pre-shared key
///
/// Returns (authenticated, server_public_key, shared_key_hash).
/// The caller should use shared_key_hash as the session encryption key for all further communication.
pub async fn auth_incoming(
    key: Arc<RwLock<[u8; 32]>>,
    trusted_addrs: Arc<RwLock<Vec<SocketAddr>>>,
    incoming_connection: (&mut TcpStream, SocketAddr),
) -> Result<(bool, [u8; 32], [u8; 32]), AuthErrors> {
    // Step 1: IP allowlist check — reject unknown peers before doing any crypto work
    if !trusted_addrs.read().await.contains(&incoming_connection.1) {
        println!(
            "Received connection from untrusted address: {}",
            incoming_connection.1
        );
        return Ok((false, [0u8; 32], [0u8; 32]));
    }

    println!(
        "Received connection from trusted address: {}",
        incoming_connection.1
    );

    // Step 2: Read the client's X25519 ephemeral public key (always exactly 32 bytes)
    let their_pub_key = &mut [0u8; 32];

    incoming_connection
        .0
        .read_exact(their_pub_key)
        .await
        .map_err(|_| AuthErrors::FailedToReadFromStream)?;

    // An all-zero public key is cryptographically invalid — reject it
    if their_pub_key == &[0u8; 32] {
        println!(
            "Received invalid public key from address: {}",
            incoming_connection.1
        );
        return Ok((false, [0u8; 32], [0u8; 32]));
    }

    // Step 3: Generate our ephemeral keypair and derive the shared secret
    // private_key is marked &mut so we can zeroize it from memory after use
    let private_key = &mut generate_private_key();
    let public_key = calculate_public_key(&private_key);
    let shared_key = &mut calculate_shared_key(&private_key, their_pub_key);

    // Hash the raw ECDH output before using it as an AES key — raw shared secrets
    // are not uniformly distributed and must not be used directly
    let shared_key_hash = hash_key(&shared_key);

    // Wipe private key and raw shared secret from memory immediately — they're no longer needed
    Zeroize::zeroize(private_key);
    Zeroize::zeroize(shared_key);

    // Step 3b: Send our public key to the client so they can compute the same shared secret
    incoming_connection
        .0
        .write_all(&public_key)
        .await
        .map_err(|_| AuthErrors::FailedToWriteToStream)?;

    // Step 4: Read the client's encrypted pre-shared key
    // Layout: [ nonce (12 bytes) | AES-GCM ciphertext (48 bytes) ] = 60 bytes total
    // Ciphertext = encrypt(pre_shared_key[32 bytes]) → 32 + 16 (GCM tag) = 48 bytes
    let e_key_buf = &mut [0u8; 60];
    let nonce = &mut [0u8; 12];

    incoming_connection
        .0
        .read_exact(e_key_buf)
        .await
        .map_err(|_| AuthErrors::FailedToReadFromStream)?;

    nonce.copy_from_slice(&e_key_buf[0..12]);

    // Step 5: Decrypt using the derived shared key — GCM will also verify integrity,
    // so any tampering or wrong key causes an error here
    let key_buf = &mut decrypt(&shared_key_hash, &e_key_buf[12..60], nonce)
        .map_err(|_| AuthErrors::FailedToDecrypt)?;

    // Wipe the encrypted buffer and nonce — plaintext key is now in key_buf
    Zeroize::zeroize(e_key_buf);
    Zeroize::zeroize(nonce);

    // Step 6: Compare decrypted key against the expected pre-shared key
    if key_buf != key.read().await.as_ref() {
        println!(
            "Authentication failed for address: {}",
            incoming_connection.1
        );
        return Ok((false, [0u8; 32], [0u8; 32]));
    }

    // Wipe the decrypted key now that comparison is done
    Zeroize::zeroize(key_buf);

    println!(
        "Authentication successful for address: {}",
        incoming_connection.1
    );

    // Return the server's public key so the caller can send it to the client,
    // and the shared_key_hash for use as the session encryption key
    Ok((true, public_key, shared_key_hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesa_conn_crypto::aes::encrypt;
    use cesa_conn_crypto::ecdh::{
        calculate_public_key, calculate_shared_key, generate_private_key, hash_key,
    };
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    const TEST_KEY: [u8; 32] = [0xAB; 32];

    /// Spins up a TCP listener, connects a client, returns (server_stream, client_stream, peer_addr)
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
    ) -> (Arc<RwLock<[u8; 32]>>, Arc<RwLock<Vec<SocketAddr>>>) {
        (Arc::new(RwLock::new(key)), Arc::new(RwLock::new(trusted)))
    }

    /// Builds the 60-byte encrypted payload a client sends after its public key.
    /// server_pub_key must be the server's known static public key.
    fn build_client_payload(server_pub_key: &[u8; 32], auth_key: &[u8; 32]) -> ([u8; 32], Vec<u8>) {
        let client_priv = generate_private_key();
        let client_pub = calculate_public_key(&client_priv);
        let shared = calculate_shared_key(&client_priv, server_pub_key);
        let shared_hash = hash_key(&shared);
        let (ciphertext, nonce) = encrypt(&shared_hash, auth_key).unwrap();
        let mut payload = Vec::with_capacity(60);
        payload.extend_from_slice(&nonce); // bytes  0..12
        payload.extend_from_slice(&ciphertext); // bytes 12..60
        (client_pub, payload)
    }

    /// Connection from an address not in the trusted list must be rejected immediately.
    #[tokio::test]
    async fn test_untrusted_addr_rejected() {
        let (mut server, _client, peer_addr) = setup_tcp_pair().await;
        let (key, trusted) = make_shared_state(TEST_KEY, vec![]);

        let result = auth_incoming(key, trusted, (&mut server, peer_addr)).await;
        assert_eq!(result.unwrap(), (false, [0u8; 32], [0u8; 32]));
    }

    /// An all-zero public key is invalid and must be rejected after reading.
    #[tokio::test]
    async fn test_zero_pubkey_rejected() {
        let (mut server, mut client, peer_addr) = setup_tcp_pair().await;
        let (key, trusted) = make_shared_state(TEST_KEY, vec![peer_addr]);

        client.write_all(&[0u8; 32]).await.unwrap();

        let result = auth_incoming(key, trusted, (&mut server, peer_addr)).await;
        assert_eq!(result.unwrap(), (false, [0u8; 32], [0u8; 32]));
    }

    /// Stream closing before sending a full public key must return FailedToReadFromStream.
    #[tokio::test]
    async fn test_incomplete_pubkey_returns_error() {
        let (mut server, mut client, peer_addr) = setup_tcp_pair().await;
        let (key, trusted) = make_shared_state(TEST_KEY, vec![peer_addr]);

        client.write_all(&[0xAB; 10]).await.unwrap();
        drop(client); // close stream early

        let result = auth_incoming(key, trusted, (&mut server, peer_addr)).await;
        assert_eq!(result.unwrap_err(), AuthErrors::FailedToReadFromStream);
    }

    /// Stream closing after pubkey but before full encrypted payload must return FailedToReadFromStream.
    #[tokio::test]
    async fn test_incomplete_encrypted_payload_returns_error() {
        let (mut server, mut client, peer_addr) = setup_tcp_pair().await;
        let (key, trusted) = make_shared_state(TEST_KEY, vec![peer_addr]);

        let client_priv = generate_private_key();
        let client_pub = calculate_public_key(&client_priv);

        client.write_all(&client_pub).await.unwrap();
        client.write_all(&[0xAB; 20]).await.unwrap(); // only 20 of 60 bytes
        drop(client);

        let result = auth_incoming(key, trusted, (&mut server, peer_addr)).await;
        assert_eq!(result.unwrap_err(), AuthErrors::FailedToReadFromStream);
    }

    /// Sending garbage bytes as the encrypted payload must fail decryption (GCM tag mismatch).
    #[tokio::test]
    async fn test_invalid_ciphertext_returns_decrypt_error() {
        let (mut server, mut client, peer_addr) = setup_tcp_pair().await;
        let (key, trusted) = make_shared_state(TEST_KEY, vec![peer_addr]);

        let client_priv = generate_private_key();
        let client_pub = calculate_public_key(&client_priv);

        client.write_all(&client_pub).await.unwrap();
        client.write_all(&[0xDE; 60]).await.unwrap(); // random garbage

        let result = auth_incoming(key, trusted, (&mut server, peer_addr)).await;
        assert_eq!(result.unwrap_err(), AuthErrors::FailedToDecrypt);
    }

    // NOTE: A full happy-path test (correct key → auth success) is not yet possible because
    // auth_incoming never sends the server's ephemeral public key back to the client.
    // The client needs it to compute the shared secret and encrypt the pre-shared key.
    // Once the protocol is fixed (see TODO in auth_incoming), add tests here:
    //   test_correct_key_auth_success
    //   test_wrong_key_auth_failure

    #[test]
    fn test_error_display_read() {
        assert_eq!(
            AuthErrors::FailedToReadFromStream.to_string(),
            "failed to read authentication key from stream"
        );
    }

    #[test]
    fn test_error_display_decrypt() {
        assert_eq!(
            AuthErrors::FailedToDecrypt.to_string(),
            "failed to decrypt authentication key"
        );
    }
}
