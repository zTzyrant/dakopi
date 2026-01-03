use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

#[derive(Serialize)]
pub struct ApiResponse<T> {
    pub status: String,
    pub code: String, 
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
}

#[derive(Serialize)]
pub struct ValidationErrorDetail {
    pub field: String,
    pub title: String,   // i18n key (e.g. "is_required", "invalid_email")
    pub message: String, // Human readable
}

impl<T> ApiResponse<T>
where
    T: Serialize,
{
    pub fn new(status: &str, code: &str, message: &str, data: Option<T>) -> Self {
        Self {
            status: status.to_string(),
            code: code.to_string(),
            message: message.to_string(),
            data,
        }
    }
}

// Wrapper to combine StatusCode and the Body
pub struct ApiResponseResult<T>(pub StatusCode, pub ApiResponse<T>);

impl<T> IntoResponse for ApiResponseResult<T>
where
    T: Serialize,
{
    fn into_response(self) -> Response {
        (self.0, Json(self.1)).into_response()
    }
}

pub struct ResponseBuilder;

impl ResponseBuilder {
    pub fn success<T: Serialize>(
        code: &str, 
        message: &str, 
        data: T
    ) -> ApiResponseResult<T> {
        ApiResponseResult(
            StatusCode::OK,
            ApiResponse::new("success", code, message, Some(data)),
        )
    }

    pub fn created<T: Serialize>(
        code: &str, 
        message: &str, 
        data: T
    ) -> ApiResponseResult<T> {
        ApiResponseResult(
            StatusCode::CREATED,
            ApiResponse::new("success", code, message, Some(data)),
        )
    }

    pub fn error<T: Serialize>(
        status_code: StatusCode,
        code: &str, 
        message: &str
    ) -> ApiResponseResult<T> {
        ApiResponseResult(
            status_code,
            ApiResponse::new("error", code, message, None),
        )
    }

    pub fn fail_with_data<T: Serialize>(
        status_code: StatusCode,
        code: &str, 
        message: &str,
        data: T
    ) -> ApiResponseResult<T> {
        ApiResponseResult(
            status_code,
            ApiResponse::new("error", code, message, Some(data)),
        )
    }
}
