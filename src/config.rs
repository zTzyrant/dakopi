use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub server_host: String,
    pub server_port: u16,
    pub database_url: String,
    pub jwt_secret: String,
    pub jwt_expires_in: i64,
}

impl Config {
    // Fungsi untuk load semua variable
    // Kalau ada satu saja yang kurang, aplikasi langsung PANIC (Gagal Start)
    // Ini bagus ("Fail Fast") daripada error di tengah jalan.
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

        Config {
            server_host,
            server_port,
            database_url,
            jwt_secret,
            jwt_expires_in,
        }
    }
}