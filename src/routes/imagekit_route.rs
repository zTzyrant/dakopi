use axum::{routing::post, Router};
use crate::config::AppState;
use crate::handlers::imagekit_handler::{get_auth_token_handler, upload_file_handler};

pub fn imagekit_routes() -> Router<AppState> {
    Router::new()
        .route("/auth", post(get_auth_token_handler))
        .route("/upload", post(upload_file_handler))
}
