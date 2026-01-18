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
mod middleware;

use config::{Config, AppState};
use dotenvy::dotenv;
use sea_orm::Database;
use std::net::SocketAddr;
use crate::services::redis_service::RedisService;

#[tokio::main]
async fn main() {
    dotenv().ok();
    
    // Set system timezone to UTC+8 (WITA)
    std::env::set_var("TZ", "Asia/Makassar");
    
    tracing_subscriber::fmt::init();

    let cfg = Config::init();
    println!("🚀 Starting Dakopi Backend...");

    // 1. Database Connection
    println!("📡 Connecting to Database...");
    let db = Database::connect(&cfg.database_url)
        .await
        .expect("🔥 Failed to connect to Database!");
    println!("✅ Database Connected!");

    // 2. Casbin Initialization
    println!("🔐 Initializing Casbin...");
    let enforcer = crate::auth::setup_casbin(db.clone()).await;

    // 3. Database Seeding
    println!("🌱 Running Seeders...");
    if let Err(e) = seeders::run_seeders(&db, &enforcer).await {
        tracing::error!("❌ Seeding failed: {}", e);
    } else {
        println!("✅ Seeding Successful!");
    }

    // 4. Redis Connection
    println!("🔌 Connecting to Redis...");
    let redis_service = RedisService::new(&cfg);
    if let Err(e) = redis_service.check_connection().await {
        tracing::error!("⚠️  Redis connection failed: {}", e);
        // On cloud environments, failing to connect to Redis should be critical
        panic!("Redis connection failed: {}", e);
    } else {
        println!("✅ Redis Connected!");
    }

    // 5. Setup Services
    let email_service = crate::services::email_service::EmailService::new(&cfg, redis_service.clone());
    let s3_service = crate::services::s3_service::S3Service::new(cfg.clone()).await;

    // 6. Build App State
    let rate_limiter = std::sync::Arc::new(
        middleware::rate_limiter::RateLimiter::new(100, std::time::Duration::from_secs(60))
    );

    let state = AppState {
        db,
        redis_service,
        email_service,
        s3_service,
        enforcer,
        rate_limiter,
    };

    // 7. Initialize Router
    let app = routes::create_routes(state.clone()).with_state(state);

    // 8. Start Server
    let addr_str = format!("{}:{}", cfg.server_host, cfg.server_port);
    let addr: SocketAddr = addr_str.parse().expect("Invalid address");

    println!("🎯 Server ready! Listening on http://{}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
