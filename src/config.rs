use std::env;
use sea_orm::DatabaseConnection;
use crate::services::redis_service::RedisService;

#[derive(Debug, Clone)]
pub struct Config {
    pub server_host: String,
    pub server_port: u16,
    pub database_url: String,
    pub jwt_secret: String,
    pub jwt_expires_in: i64,
    pub redis_url: String,
    pub smtp_from: String,
    pub brevo_api_key: String,
    pub reset_hash_key: String,
    pub imagekit_private_key: String,
    pub imagekit_public_key: String,
    pub imagekit_url_endpoint: String,
}

#[derive(Clone, axum::extract::FromRef)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub redis_service: RedisService,
    pub email_service: crate::services::email_service::EmailService,
    pub imagekit_service: crate::services::imagekit_service::ImageKitService,
    pub enforcer: crate::auth::SharedEnforcer,
    pub rate_limiter: std::sync::Arc<crate::middleware::rate_limiter::RateLimiter>,
}

impl Config {
    pub fn init() -> Config {
        let server_host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let server_port = env::var("PORT")
            .unwrap_or_else(|_| "3000".to_string())
            .parse::<u16>()
            .expect("PORT harus berupa angka");

        let database_url = env::var("DATABASE_URL").expect("DATABASE_URL wajib diisi di .env");
        let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET wajib diisi di .env");
        let jwt_expires_in = env::var("JWT_EXPIRATION_MINUTES")
            .unwrap_or_else(|_| "15".to_string())
            .parse::<i64>()
            .expect("JWT_EXPIRATION_MINUTES harus angka");
        
        let redis_url = std::env::var("REDIS_URL").expect("REDIS_URL wajib");
        
        let smtp_from = env::var("SMTP_FROM").unwrap_or_else(|_| "admin@dakopi.dev".to_string());
        let brevo_api_key = env::var("BREVO_API_KEY").unwrap_or_default();
        let reset_hash_key = env::var("RESET_HASH_KEY").unwrap_or_else(|_| "default_secret".to_string());

        let imagekit_private_key = env::var("IMAGEKIT_PRIVATE_KEY").expect("IMAGEKIT_PRIVATE_KEY must be set");
        let imagekit_public_key = env::var("IMAGEKIT_PUBLIC_KEY").expect("IMAGEKIT_PUBLIC_KEY must be set");
        let imagekit_url_endpoint = env::var("IMAGEKIT_URL_ENDPOINT").expect("IMAGEKIT_URL_ENDPOINT must be set");

        Config {
            server_host,
            server_port,
            database_url,
            jwt_secret,
            jwt_expires_in,
            redis_url,
            smtp_from,
            brevo_api_key,
            reset_hash_key,
            imagekit_private_key,
            imagekit_public_key,
            imagekit_url_endpoint,
        }
    }
}