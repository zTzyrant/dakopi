use axum::Router;
use crate::config::AppState;

pub mod admin_route;
pub mod auth_route;
pub mod imagekit_route;
pub mod article_route;
pub mod media_route;

pub fn create_routes(state: AppState) -> Router<AppState> {
    Router::new()
        .nest("/api/auth", auth_route::auth_routes(state.clone()))
        .nest("/api/admin", admin_route::admin_routes(state.clone()))
        .nest("/api/imagekit", imagekit_route::imagekit_routes())
        .nest("/api/articles", article_route::article_routes(state.clone()))
        .nest("/api/media", media_route::media_routes(state.clone()))
        // Health check
        .route("/api/health", axum::routing::get(|| async { "OK" }))
}
