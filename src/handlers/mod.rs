pub mod auth_handler;
pub mod admin_handler;
pub mod imagekit_handler;

use axum::response::IntoResponse;
use chrono::{Utc, FixedOffset};
use crate::utils::api_response::ResponseBuilder;

pub async fn health_check_handler() -> impl IntoResponse {
    let offset = FixedOffset::east_opt(8 * 3600).unwrap();
    let now = Utc::now().with_timezone(&offset);

    ResponseBuilder::success(
        "HEALTH_CHECK_SUCCESS",
        "Server is healthy",
        serde_json::json!({
            "status": "up",
            "server_time": now.to_rfc3339(),
            "timezone": "UTC+8 (WITA)"
        })
    )
}
