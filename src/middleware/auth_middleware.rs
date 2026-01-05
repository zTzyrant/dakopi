use crate::config::AppState;
use crate::utils::api_response::ResponseBuilder; // Import ResponseBuilder kamu
use crate::utils::jwt_utils::JwtUtils;
use axum::{
    body::Body,
    extract::State,
    http::{header, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use casbin::CoreApi;
use jsonwebtoken::errors::ErrorKind;

pub async fn rbac_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> std::result::Result<Response, StatusCode> {
    // 1. Get Token from Header
    let auth_header = match req.headers().get(header::AUTHORIZATION) {
        Some(header) => header,
        None => {
            // Menggunakan ResponseBuilder
            return Ok(ResponseBuilder::error::<()>(
                StatusCode::UNAUTHORIZED,
                "AUTH_MISSING",
                "Authorization header is missing",
            )
            .into_response());
        }
    };

    let auth_str = match auth_header.to_str() {
        Ok(s) => s,
        Err(_) => {
            return Ok(ResponseBuilder::error::<()>(
                StatusCode::UNAUTHORIZED,
                "AUTH_INVALID_FORMAT",
                "Invalid Authorization header format",
            )
            .into_response());
        }
    };

    if !auth_str.starts_with("Bearer ") {
        return Ok(ResponseBuilder::error::<()>(
            StatusCode::UNAUTHORIZED,
            "AUTH_INVALID_SCHEME",
            "Invalid token format. Missing 'Bearer ' prefix",
        )
        .into_response());
    }

    let token = &auth_str[7..];

    // 2. Validate JWT
    let token_data = match JwtUtils::validate_jwt(token) {
        Ok(data) => data,
        Err(e) => {
            // Deteksi jenis error token
            let (code, message) = match e.kind() {
                ErrorKind::ExpiredSignature => ("TOKEN_EXPIRED", "Token has expired"),
                ErrorKind::InvalidToken => ("TOKEN_INVALID", "Token is invalid"),
                ErrorKind::InvalidSignature => ("TOKEN_BAD_SIGNATURE", "Invalid token signature"),
                _ => ("AUTH_FAILED", "Authentication failed"),
            };

            tracing::error!("JWT Validation failed: {}", e);

            // Return error menggunakan standar ResponseBuilder kamu
            return Ok(
                ResponseBuilder::error::<()>(StatusCode::UNAUTHORIZED, code, message)
                    .into_response(),
            );
        }
    };

    let user_sub = token_data.claims.sub.to_string();

    // 3. Get Path and Method
    let path = req.uri().path().to_string();
    let method = req.method().to_string();

    // 4. Check Permission via Casbin
    let enforcer = state.enforcer.read().await;

    match enforcer.enforce((&user_sub, &path, &method)) {
        Ok(true) => Ok(next.run(req).await),
        Ok(false) => {
            tracing::warn!("Access denied for user {} at {} {}", user_sub, method, path);

            // Return Forbidden Error
            Ok(ResponseBuilder::error::<()>(
                StatusCode::FORBIDDEN,
                "ACCESS_DENIED",
                "You do not have permission to access this resource",
            )
            .into_response())
        }
        Err(e) => {
            tracing::error!("Casbin enforce error: {}", e);

            // Internal Server Error
            Ok(ResponseBuilder::error::<()>(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "An internal error occurred during permission check",
            )
            .into_response())
        }
    }
}
