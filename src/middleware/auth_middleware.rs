use crate::config::AppState;
use crate::utils::api_response::ResponseBuilder;
use crate::utils::jwt_utils::JwtUtils;
use crate::models::auth_model::{CurrentUser, UserData};
use crate::entities::{user, user_role, role};
use axum::{
    body::Body,
    extract::State,
    http::{header, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use casbin::CoreApi;
use jsonwebtoken::errors::ErrorKind;
use sea_orm::{EntityTrait, QueryFilter, ColumnTrait};

pub async fn rbac_middleware(
    State(state): State<AppState>,
    mut req: Request<Body>,
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
    let user_id = claims.sub;

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

    // 4. Get User Data (Cache -> DB)
    let user_cache_key = format!("user:{}", user_id);
    let cached_user: Option<UserData> = state.redis_service.get(&user_cache_key).await;

    let user_data = if let Some(user) = cached_user {
        // Cache Hit
        user
    } else {
        // Cache Miss
        let user = fetch_user_from_db(&state.db, user_id).await?;
        
        // Cache it (TTL 15 mins matching access token default)
        let _ = state.redis_service.set(&user_cache_key, &user, 15 * 60).await;
        user
    };
    
    // Construct CurrentUser with Session ID from token
    let current_user = CurrentUser {
        id: user_data.id,
        username: user_data.username,
        email: user_data.email,
        roles: user_data.roles,
        session_id: claims.sid,
    };

    // 5. Inject CurrentUser into request
    req.extensions_mut().insert(current_user.clone());

    // 6. Casbin Enforce
    let enforcer = state.enforcer.read().await;
    let path = req.uri().path().to_string();
    let method = req.method().to_string();
    
    match enforcer.enforce((&user_id.to_string(), &path, &method)) {
        Ok(true) => Ok(next.run(req).await),
        Ok(false) => {
            tracing::warn!("Access denied for user {} at {} {}", user_id, method, path);
            Ok(ResponseBuilder::error::<()>(
                StatusCode::FORBIDDEN,
                "ACCESS_DENIED",
                "You do not have permission to access this resource",
            )
            .into_response())
        }
        Err(e) => {
            tracing::error!("Casbin enforce error: {}", e);
            Ok(ResponseBuilder::error::<()>(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "An internal error occurred during permission check",
            )
            .into_response())
        }
    }
}

async fn fetch_user_from_db(
    db: &sea_orm::DatabaseConnection,
    user_id: uuid::Uuid,
) -> Result<UserData, StatusCode> {
    // Fetch User
    let user = user::Entity::find()
        .filter(user::Column::PublicId.eq(user_id))
        .one(db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Fetch Roles
    // Join user -> user_roles -> roles
    let roles: Vec<String> = user_role::Entity::find()
        .filter(user_role::Column::UserId.eq(user.id))
        .find_also_related(role::Entity)
        .all(db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .into_iter()
        .filter_map(|(_ur, r)| r.map(|role| role.name))
        .collect();

    Ok(UserData {
        id: user.public_id,
        username: user.username,
        email: user.email,
        roles,
    })
}
