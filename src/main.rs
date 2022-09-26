#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let app = axum::Router::new().route("/healthz", axum::routing::get(healthz));
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], 10067));
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn healthz() -> axum::response::Result<(axum::http::StatusCode, &'static str)> {
    return Ok((axum::http::StatusCode::OK, "ok"));
}
