mod config;
mod entities;
mod services;
mod handlers;
mod routes;
mod repositories;
mod utils;
mod models;
mod seeders;
mod auth;

use config::{Config, AppState};
use dotenvy::dotenv;
use sea_orm::Database;
use std::net::SocketAddr;
use crate::services::redis_service::RedisService;

#[tokio::main]
async fn main() {
    dotenv().ok();
    
    // Set Timezone ke UTC+8 (WITA)
    std::env::set_var("TZ", "Asia/Makassar");
    
    tracing_subscriber::fmt::init();

    let cfg = Config::init();
    println!("🚀 Memulai Dakopi Backend...");

    // 1. Konek Database
    let db = Database::connect(&cfg.database_url)
        .await
        .expect("🔥 Gagal konek Database!");
    println!("✅ Database Connected!");

    // Setup Redis
    let redis_service = RedisService::new(&cfg);
    if let Err(e) = redis_service.check_connection().await {
        tracing::warn!("⚠️  Redis connection failed: {}", e);
    } else {
        println!("✅ Redis Connected!");
    }

    // Setup Email Service
    let email_service = crate::services::email_service::EmailService::new(&cfg, redis_service.clone());

    // Setup Casbin
    let enforcer = crate::auth::setup_casbin(db.clone()).await;

    // Jalankan Seeder
    if let Err(e) = seeders::run_seeders(&db, &enforcer).await {
        tracing::error!("❌ Seeding failed: {}", e);
    }

    // Gabungkan ke AppState
    let state = AppState {
        db,
        redis_service,
        email_service,
        enforcer,
    };

    // 2. Setup Router
    let app = routes::create_routes().with_state(state);

    // 3. Run Server
    let addr_str = format!("{}:{}", cfg.server_host, cfg.server_port);
    let addr: SocketAddr = addr_str.parse().expect("Invalid address");

    println!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
