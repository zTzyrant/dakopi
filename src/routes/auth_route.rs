use axum::{routing::{post, get, delete}, Router, middleware};
use crate::config::AppState;
use crate::handlers::auth_handler::*;
use crate::middleware::{rate_limiter::rate_limit_middleware, auth_middleware::rbac_middleware};

// Return Router<AppState> because handlers now use AppState
pub fn auth_routes(state: AppState) -> Router<AppState> {
    let public_routes = Router::new()
        .route("/register", post(register_user_handler))
        .route("/login", post(login_user_handler))
        .route("/refresh", post(refresh_token_handler))
        .route("/verify-email", post(verify_email_handler))
        .route("/password/forgot", post(forgot_password_handler))
        .route("/password/reset", post(reset_password_handler))
        .route("/2fa/verify-login", post(verify_2fa_login_handler))
        .route("/oauth/{provider}", get(get_oauth_url_handler))
        .route("/oauth/{provider}/callback", get(oauth_callback_handler)); // Verify login is public (part of login flow)

    let protected_routes = Router::new()
        .route("/logout", post(logout_handler))
        .route("/reset-limit", post(reset_email_limit_handler))
        .route("/roles", get(get_roles_handler))
        .route("/profile", get(profile_handler))
        .route("/2fa/setup", post(setup_2fa_handler))
        .route("/2fa/confirm", post(confirm_2fa_handler))
        .route("/2fa/disable", post(disable_2fa_handler))
        // Session Management
        .route("/sessions", get(get_sessions_handler).delete(revoke_all_sessions_handler))
        .route("/sessions/{id}", delete(revoke_session_handler))
        .route_layer(middleware::from_fn_with_state(state.clone(), rbac_middleware));

    public_routes
        .merge(protected_routes)
        .route_layer(middleware::from_fn_with_state(state, rate_limit_middleware))
}
