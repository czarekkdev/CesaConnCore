
pub mod udp_networker;

#[tokio::main]
async fn main() {
    let _addr = udp_networker::udp_find_broadcaster(21).await;

    if _addr.is_none() {
        eprintln!("Fail!");
    } else {
        println!("Ip: {}", _addr.unwrap().ip());
    }
}