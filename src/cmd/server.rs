pub async fn serve() {
    let app = axum::Router::new().route("/healthz", axum::routing::get(healthz));
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], 10067));
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

// if let Some(l) = listenfd::ListenFd::from_env().take_tcp_listener(0)? {
// axum::Server::from_tcp(l)?
// } else  {
// axum::Server::bind(&std::net::SocketAddr::from([127,0,0,1],3000))
// }.serve(app.into_make_service()).await.unwrap();

async fn healthz() -> axum::response::Result<(axum::http::StatusCode, &'static str)> {
    Ok((axum::http::StatusCode::OK, "ok"))
}
