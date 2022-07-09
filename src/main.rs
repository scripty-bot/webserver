#[tokio::main]
async fn main() {
    server_core::run_server().await;
}
