use axum::{routing::{get, post, delete}, Router};
use crate::config::AppState;
use crate::handlers::admin_handler::*;

pub fn admin_routes() -> Router<AppState> {
    Router::new()
        .nest("/casbin", Router::new()
            .route("/policies", get(list_policies_handler))
            .route("/policy", post(add_policy_handler))
            .route("/policy", delete(remove_policy_handler))
        )
}
