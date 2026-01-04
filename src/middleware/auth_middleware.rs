use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode, header},
    middleware::Next,
    response::Response,
};
use crate::config::{Config, AppState};
use crate::models::auth_model::Claims;
use casbin::CoreApi;
use jsonwebtoken::{decode, DecodingKey, Validation};

pub async fn rbac_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> std::result::Result<Response, StatusCode> {
    // 1. Get Token from Header
    let auth_header = req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if !auth_header.starts_with("Bearer ") {
         return Err(StatusCode::UNAUTHORIZED);
    }

    let token = &auth_header[7..];

    // 2. Validate JWT
    let cfg = Config::init(); 
    let decoding_key = DecodingKey::from_secret(cfg.jwt_secret.as_bytes());
    let mut validation = Validation::default();
    validation.validate_exp = true;

    let token_data = decode::<Claims>(token, &decoding_key, &validation)
        .map_err(|e| {
            tracing::error!("JWT Validation failed: {}", e);
            StatusCode::UNAUTHORIZED
        })?;

    let user_sub = token_data.claims.sub.to_string(); // UUID string
    
    // 3. Get Path and Method
    let path = req.uri().path().to_string();
    let method = req.method().to_string();

    // 4. Check Permission via Casbin
    let enforcer = state.enforcer.read().await;
    
    // Casbin check: (user_uuid, path, method)
    // Casbin should have grouping policies g(user_uuid, role) 
    // and policies p(role, path, method, allow)
    match enforcer.enforce((&user_sub, &path, &method)) {
        Ok(true) => Ok(next.run(req).await),
        Ok(false) => {
            tracing::warn!("Access denied for user {} at {} {}", user_sub, method, path);
            Err(StatusCode::FORBIDDEN)
        },
        Err(e) => {
            tracing::error!("Casbin enforce error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
