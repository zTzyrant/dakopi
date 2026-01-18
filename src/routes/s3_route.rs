use axum::{routing::post, Router, middleware};
use crate::config::AppState;
use crate::handlers::s3_handler::{upload_file_handler, get_presigned_url_handler};
use crate::middleware::{rate_limiter::rate_limit_middleware, jwt_middleware::jwt_middleware};

pub fn s3_routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/upload", post(upload_file_handler))
        .route("/presigned", post(get_presigned_url_handler))
        .layer(middleware::from_fn_with_state(state.clone(), jwt_middleware))
        .layer(middleware::from_fn_with_state(state, rate_limit_middleware))
}