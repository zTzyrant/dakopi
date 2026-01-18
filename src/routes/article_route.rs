use axum::{routing::get, Router, middleware};
use crate::config::AppState;
use crate::handlers::article_handler::*;
use crate::middleware::{rate_limiter::rate_limit_middleware, auth_middleware::rbac_middleware};

pub fn article_routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/tags", get(list_tags_handler).post(create_tag_handler))
        .route("/", get(list_articles_handler).post(create_article_handler))
        .route("/{id}", get(get_article_handler).put(update_article_handler).delete(delete_article_handler))
        .layer(middleware::from_fn_with_state(state.clone(), rbac_middleware))
        .layer(middleware::from_fn_with_state(state, rate_limit_middleware))
}
