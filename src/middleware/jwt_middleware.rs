use crate::config::AppState;
use crate::utils::api_response::ResponseBuilder;
use crate::utils::jwt_utils::JwtUtils;
use axum::{
    body::Body,
    extract::State,
    http::{header, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use jsonwebtoken::errors::ErrorKind;

pub async fn jwt_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> std::result::Result<Response, StatusCode> {
    // 1. Get Token from Header
    let auth_header = match req.headers().get(header::AUTHORIZATION) {
        Some(header) => header,
        None => {
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
            let (code, message) = match e.kind() {
                ErrorKind::ExpiredSignature => ("TOKEN_EXPIRED", "Token has expired"),
                ErrorKind::InvalidToken => ("TOKEN_INVALID", "Token is invalid"),
                ErrorKind::InvalidSignature => ("TOKEN_BAD_SIGNATURE", "Invalid token signature"),
                _ => ("AUTH_FAILED", "Authentication failed"),
            };

            return Ok(
                ResponseBuilder::error::<()>(StatusCode::UNAUTHORIZED, code, message)
                    .into_response(),
            );
        }
    };

    let claims = token_data.claims;

    // 3. Check Blacklist (Redis)
    let blacklist_key = format!("blacklist:token:{}", claims.jti);
    let is_blacklisted = state.redis_service.exists(&blacklist_key).await;

    if is_blacklisted {
        return Ok(ResponseBuilder::error::<()>(
            StatusCode::UNAUTHORIZED,
            "TOKEN_REVOKED",
            "This session has been logged out",
        ).into_response());
    }
    
    // Token valid, proceed
    Ok(next.run(req).await)
}
