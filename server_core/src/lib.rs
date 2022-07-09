pub async fn run_server() {
    let config = server_config::read_config("config.toml");
    let app = axum::Router::new();
    axum::Server::bind(&([127, 0, 0, 1], config.port).into()).serve(app.into_make_service()).await.expect("Failed to run server");
}
