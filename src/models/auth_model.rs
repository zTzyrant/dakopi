use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Deserialize, Validate)]
pub struct RegisterRequest {
    #[serde(default)]
    #[validate(custom(function = "crate::utils::validator_utils::validate_required"))]
    #[validate(length(min = 3, message = "Username must be at least 3 characters"))]
    pub username: String,
    
    #[serde(default)]
    #[validate(custom(function = "crate::utils::validator_utils::validate_required"))]
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    
    #[serde(default)]
    #[validate(custom(function = "crate::utils::validator_utils::validate_required"))]
    #[validate(length(min = 6, message = "Password must be at least 6 characters"))]
    pub password: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub id: Uuid,
    pub username: String,
    pub email: String,
}

#[derive(Deserialize, Validate)]
pub struct LoginRequest {
    #[serde(default)]
    #[validate(custom(function = "crate::utils::validator_utils::validate_required"))]
    pub login_id: String, // Email OR Username
    
    #[serde(default)]
    #[validate(custom(function = "crate::utils::validator_utils::validate_required"))]
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub type_: String,
}