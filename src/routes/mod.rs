pub mod auth_route; // Daftarkan modul auth.rs

use axum::{routing::get, Router};
use sea_orm::DatabaseConnection;
use auth_route::auth_routes;



// Ini fungsi utama yang dipanggil di main.rs
pub fn create_routes() -> Router<DatabaseConnection> {
  let health_check = Router::new().route("/health", get(|| async {"OK"}));
  let api_routes = Router::new().nest("/health", health_check).nest("/auth", auth_routes());

  Router::new().nest("/api", api_routes)
}