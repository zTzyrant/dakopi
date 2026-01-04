pub mod auth_route; 
pub mod admin_route;

use crate::config::AppState;
use axum::{routing::get, Router};
use auth_route::auth_routes;
use admin_route::admin_routes;
use crate::handlers::health_check_handler;
use crate::utils::api_response::ResponseBuilder;

// Ini fungsi utama yang dipanggil di main.rs
pub fn create_routes() -> Router<AppState> {
  let api_routes = Router::new()
    .route("/health", get(health_check_handler))
    .nest("/auth", auth_routes())
    .nest("/admin", admin_routes());

  Router::new()
  .route("/", 
    get(|| async { 
      ResponseBuilder::success("SUCCESS", "Welcome to Dakopi API", "")
    })
  )
  .nest("/api", api_routes)
}
