use axum::{
    extract::State,
    response::IntoResponse,
};
use sea_orm::DatabaseConnection;

use crate::models::auth_model::{LoginRequest, LoginResponse, RegisterRequest, RegisterResponse};
use crate::services::auth_service::AuthService;
use crate::utils::api_response::ResponseBuilder;
use crate::utils::validated_wrapper::ValidatedJson; 

// 1. HANDLER REGISTER
pub async fn register_user_handler(
    State(db): State<DatabaseConnection>,
    ValidatedJson(payload): ValidatedJson<RegisterRequest>,
) -> impl IntoResponse {
    
    match AuthService::register_user(
        &db, 
        payload.username, 
        payload.email, 
        payload.password
    ).await {
        Ok(user) => ResponseBuilder::created(
            "AUTH_REGISTER_SUCCESS",
            "User registered successfully",
            RegisterResponse {
                id: user.public_id,
                username: user.username,
                email: user.email,
            }
        ),
        // Message is now String, so we pass reference &message
        Err((status, code, message)) => ResponseBuilder::error(status, code, &message),
    }
}

// 2. HANDLER LOGIN
pub async fn login_user_handler(
    State(db): State<DatabaseConnection>,
    ValidatedJson(payload): ValidatedJson<LoginRequest>,
) -> impl IntoResponse {

    match AuthService::login_user(
        &db, 
        payload.login_id, 
        payload.password
    ).await {
        Ok((token, type_)) => ResponseBuilder::success(
            "AUTH_LOGIN_SUCCESS",
            "Login successful",
            LoginResponse { token, type_ }
        ),
        // Message is now String, so we pass reference &message
        Err((status, code, message)) => ResponseBuilder::error(status, code, &message),
    }
}
