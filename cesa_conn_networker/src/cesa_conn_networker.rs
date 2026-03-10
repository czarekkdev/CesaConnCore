
pub mod udp_networker;
pub mod tcp_networker;

#[tokio::main]
async fn main() {
    let addr = udp_networker::udp_find_broadcaster(21).await;

    if addr.is_none() {
        eprintln!("Fail!");
    } else {
        println!("Ip: {}", addr.unwrap().ip());
    }
}