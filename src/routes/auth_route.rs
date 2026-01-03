use axum::{routing::post, Router};
use sea_orm::DatabaseConnection;
use crate::handlers::auth_handler::{register_user_handler, login_user_handler};

// Kita kembalikan Router yang State-nya adalah DatabaseConnection
pub fn auth_routes() -> Router<DatabaseConnection> {
    Router::new()
        .route("/register", post(register_user_handler))
        .route("/login", post(login_user_handler))
}