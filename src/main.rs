mod config;
mod entities;
mod services;
mod handlers;
mod routes;
mod repositories;
mod utils;
mod models;

use config::Config;
use dotenvy::dotenv;
use sea_orm::Database;
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    dotenv().ok();
    tracing_subscriber::fmt::init();

    let config = Config::init();
    println!("🚀 Memulai Dakopi Backend...");

    // 1. Konek Database
    let db = Database::connect(&config.database_url)
        .await
        .expect("🔥 Gagal konek Database!");
    println!("✅ Database Connected!");

    // 2. Setup Router (Panggil dari routes::create_routes)
    let app = routes::create_routes()
        .with_state(db); // <-- Inject DB State di sini, untuk semua routes

    // 3. Run Server
    let addr_str = format!("{}:{}", config.server_host, config.server_port);
    let addr: SocketAddr = addr_str.parse().expect("Invalid address");

    println!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}