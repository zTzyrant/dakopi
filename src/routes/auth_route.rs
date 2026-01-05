use axum::{routing::{post, get}, Router, middleware};
use crate::config::AppState;
use crate::handlers::auth_handler::*;
use crate::middleware::rate_limiter::rate_limit_middleware;

// Return Router<AppState> because handlers now use AppState
pub fn auth_routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/register", post(register_user_handler))
        .route("/login", post(login_user_handler))
        .route("/refresh", post(refresh_token_handler))
        .route("/logout", post(logout_handler))
        .route("/verify-email", post(verify_email_handler))
        .route("/password/forgot", post(forgot_password_handler))
        .route("/password/reset", post(reset_password_handler))
        .route("/reset-limit", post(reset_email_limit_handler))
        .route("/roles", get(get_roles_handler))
        .route("/profile", get(profile_handler))
        .route_layer(middleware::from_fn_with_state(state, rate_limit_middleware))
}
