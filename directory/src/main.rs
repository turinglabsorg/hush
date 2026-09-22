use std::net::SocketAddr;

use hush_directory::router;
use hush_directory::serve_store;

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(8080);
    let app = router(serve_store());
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    eprintln!("hush-directory listening on {addr}");
    axum::serve(listener, app).await.expect("serve");
}
