use axum::{routing::{post, get}, Router};
use crate::config::AppState;
use crate::handlers::auth_handler::*;

// Return Router<AppState> because handlers now use AppState
pub fn auth_routes() -> Router<AppState> {
    Router::new()
        .route("/register", post(register_user_handler))
        .route("/login", post(login_user_handler))
        .route("/refresh", post(refresh_token_handler))
        .route("/reset-limit", post(reset_email_limit_handler))
        .route("/roles", get(get_roles_handler))
        .route("/profile", get(profile_handler))
}
