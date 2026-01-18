use crate::config::AppState;
use axum::http::Method;
use axum::Router;
use tower_http::cors::{Any, CorsLayer};

pub mod admin_route;
pub mod article_route;
pub mod auth_route;
pub mod media_route;
pub mod s3_route;

pub fn create_routes(state: AppState) -> Router<AppState> {
    let cors = CorsLayer::new()
        // Allow `GET`, `POST`, `OPTIONS`, `PUT`, `DELETE` methods
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::OPTIONS,
            Method::PUT,
            Method::DELETE,
        ])
        // Allow requests from any origin
        .allow_origin(Any)
        // Allow any headers
        .allow_headers(Any);

    Router::new()
        .nest("/api/auth", auth_route::auth_routes(state.clone()))
        .nest("/api/admin", admin_route::admin_routes(state.clone()))
        .nest(
            "/api/articles",
            article_route::article_routes(state.clone()),
        )
        .nest("/api/media", media_route::media_routes(state.clone()))
        .nest("/api/s3", s3_route::s3_routes(state.clone()))
        // Health check
        .route("/api/health", axum::routing::get(|| async { "OK" }))
        .layer(cors)
}
