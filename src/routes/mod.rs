pub mod auth_route; 
pub mod admin_route;
pub mod imagekit_route;

use crate::config::AppState;
use axum::{routing::get, Router};
use auth_route::auth_routes;
use admin_route::admin_routes;
use imagekit_route::imagekit_routes;
use crate::handlers::health_check_handler;
use crate::utils::api_response::ResponseBuilder;

// Ini fungsi utama yang dipanggil di main.rs
pub fn create_routes(state: AppState) -> Router<AppState> {
  let api_routes = Router::new()
    .route("/health", get(health_check_handler))
    .nest("/auth", auth_routes(state.clone()))
    .nest("/admin", admin_routes(state.clone()))
    .nest("/imagekit", imagekit_routes());

  Router::new()
  .route("/", 
    get(|| async { 
      ResponseBuilder::success("SUCCESS", "Welcome to Dakopi API", "")
    })
  )
  .nest("/api", api_routes)
}
