use axum::{routing::{get, post, delete}, Router};
use crate::config::AppState;
use crate::handlers::admin_handler::*;

pub fn admin_routes(state: AppState) -> Router<AppState> {
    Router::new()
        .nest("/casbin", Router::new()
            .route("/policies", get(list_policies_handler))
            .route("/policy", post(add_policy_handler))
            .route("/policy", delete(remove_policy_handler))
            .route("/cleanup", post(cleanup_policies_handler))
        )
        .layer(axum::middleware::from_fn_with_state(
            state,
            crate::middleware::auth_middleware::rbac_middleware
        ))
}
