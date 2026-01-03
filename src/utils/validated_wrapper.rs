use axum::{
    extract::{FromRequest, Request},
    http::StatusCode,
    Json,
    response::IntoResponse,
};
use validator::{Validate, ValidationErrors};
use crate::utils::api_response::{ResponseBuilder, ValidationErrorDetail};

pub struct ValidatedJson<T>(pub T);

impl<T, S> FromRequest<S> for ValidatedJson<T>
where
    T: serde::de::DeserializeOwned + Validate,
    S: Send + Sync,
{
    type Rejection = axum::response::Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        // 1. JSON Extraction
        let Json(payload) = Json::<T>::from_request(req, state)
            .await
            .map_err(|err| {
                let message = format!("Invalid JSON format: {}", err.body_text());
                ResponseBuilder::error::<()>(
                    StatusCode::BAD_REQUEST,
                    "INVALID_JSON",
                    &message,
                ).into_response()
            })?;

        // 2. Logic Validation
        if let Err(e) = payload.validate() {
            let error_list = map_validation_errors(e);

            return Err(ResponseBuilder::fail_with_data(
                StatusCode::BAD_REQUEST,
                "VALIDATION_ERROR",
                "Validation failed",
                error_list,
            ).into_response());
        }

        Ok(ValidatedJson(payload))
    }
}

// Convert validator errors to our custom struct list
fn map_validation_errors(errors: ValidationErrors) -> Vec<ValidationErrorDetail> {
    let mut details = Vec::new();

    for (field, error_kind) in errors.field_errors() {
        for err in error_kind {
            details.push(ValidationErrorDetail {
                field: field.to_string(),
                title: err.code.to_string(), // Uses "is_required", "email", etc.
                message: err.message.clone().map(|m| m.to_string()).unwrap_or_else(|| "Invalid value".to_string()),
            });
        }
    }

    details
}
