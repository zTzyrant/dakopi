use std::env;
use sea_orm::DatabaseConnection;
use crate::services::redis_service::RedisService;

#[derive(Debug, Clone)]
pub struct Config {
    pub server_host: String,
    pub server_port: u16,
    pub database_url: String,
    pub jwt_secret: String,
    pub jwt_access_minutes: i64,
    pub jwt_refresh_days: i64,
    pub jwt_remember_days: i64,
    pub redis_url: String,
    pub smtp_from: String,
    pub brevo_api_key: String,
    pub reset_hash_key: String,
    pub s3_endpoint: String,
    pub s3_access_key: String,
    pub s3_secret_key: String,
    pub s3_bucket_name: String,
    pub s3_region: String,
    pub google_client_id: String,
    pub google_client_secret: String,
    pub google_redirect_url: String,
    pub github_client_id: String,
    pub github_client_secret: String,
    pub github_redirect_url: String,
}

#[derive(Clone, axum::extract::FromRef)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub redis_service: RedisService,
    pub email_service: crate::services::email_service::EmailService,
    pub s3_service: crate::services::s3_service::S3Service,
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
        
        let jwt_access_minutes = env::var("JWT_ACCESS_MINUTES")
            .unwrap_or_else(|_| "15".to_string())
            .parse::<i64>()
            .expect("JWT_ACCESS_MINUTES harus angka");
            
        let jwt_refresh_days = env::var("JWT_REFRESH_DAYS")
            .unwrap_or_else(|_| "7".to_string())
            .parse::<i64>()
            .expect("JWT_REFRESH_DAYS harus angka");

        let jwt_remember_days = env::var("JWT_REMEMBER_DAYS")
            .unwrap_or_else(|_| "30".to_string())
            .parse::<i64>()
            .expect("JWT_REMEMBER_DAYS harus angka");
        
        let redis_url = std::env::var("REDIS_URL").expect("REDIS_URL wajib");
        
        let smtp_from = env::var("SMTP_FROM").unwrap_or_else(|_| "admin@dakopi.dev".to_string());
        let brevo_api_key = env::var("BREVO_API_KEY").unwrap_or_default();
        let reset_hash_key = env::var("RESET_HASH_KEY").unwrap_or_else(|_| "default_secret".to_string());

        let s3_endpoint = env::var("S3_ENDPOINT").expect("S3_ENDPOINT wajib diisi");
        let s3_access_key = env::var("S3_ACCESS_KEY").expect("S3_ACCESS_KEY wajib diisi");
        let s3_secret_key = env::var("S3_SECRET_KEY").expect("S3_SECRET_KEY wajib diisi");
        let s3_bucket_name = env::var("S3_BUCKET_NAME").expect("S3_BUCKET_NAME wajib diisi");
        let s3_region = env::var("S3_REGION").unwrap_or_else(|_| "auto".to_string());

        let google_client_id = env::var("GOOGLE_CLIENT_ID").unwrap_or_default();
        let google_client_secret = env::var("GOOGLE_CLIENT_SECRET").unwrap_or_default();
        let google_redirect_url = env::var("GOOGLE_REDIRECT_URL").unwrap_or_default();

        let github_client_id = env::var("GITHUB_CLIENT_ID").unwrap_or_default();
        let github_client_secret = env::var("GITHUB_CLIENT_SECRET").unwrap_or_default();
        let github_redirect_url = env::var("GITHUB_REDIRECT_URL").unwrap_or_default();

        Config {
            server_host,
            server_port,
            database_url,
            jwt_secret,
            jwt_access_minutes,
            jwt_refresh_days,
            jwt_remember_days,
            redis_url,
            smtp_from,
            brevo_api_key,
            reset_hash_key,
            s3_endpoint,
            s3_access_key,
            s3_secret_key,
            s3_bucket_name,
            s3_region,
            google_client_id,
            google_client_secret,
            google_redirect_url,
            github_client_id,
            github_client_secret,
            github_redirect_url,
        }
    }
}