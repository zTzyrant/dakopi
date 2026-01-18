use axum::{routing::{get, post, delete}, Router, middleware};
use crate::config::AppState;
use crate::handlers::media_handler::*;
use crate::middleware::{rate_limiter::rate_limit_middleware, auth_middleware::rbac_middleware};

pub fn media_routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/upload", post(upload_media_handler))
        .route("/check-nsfw", post(check_nsfw_handler))
        .route("/{id}", delete(delete_media_handler))
        .route("/", get(list_media_handler))
        .layer(middleware::from_fn_with_state(state.clone(), rbac_middleware))
        .layer(middleware::from_fn_with_state(state, rate_limit_middleware))
}
