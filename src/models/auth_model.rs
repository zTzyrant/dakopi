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

    #[serde(default)]
    pub remember_me: bool,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub token_expires_at: usize,
    pub refresh_token: Option<String>,
    pub refresh_token_expires_at: Option<usize>,
    pub type_: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: Uuid,      
    // Username removed for minimal payload
    pub sid: Uuid, // Session ID (to track current session)
    pub exp: usize,     
    pub iat: usize,     
    pub jti: String, // Access Token Unique ID (for blacklist)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserData {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentUser {
    pub id: Uuid, // Public ID
    pub session_id: Uuid, // Current Session ID
    pub username: String,
    pub email: String,
    pub roles: Vec<String>,
}

#[derive(Deserialize, Validate)]
pub struct ResetEmailLimitRequest {
    #[serde(default)]
    #[validate(custom(function = "crate::utils::validator_utils::validate_required"))]
    pub secret: String,
}

#[derive(Serialize)]
pub struct RoleInfo {
    pub id: Uuid, // Public UUID
    pub name: String,
}

#[derive(Serialize)]
pub struct ProfileResponse {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub roles: Vec<RoleInfo>,
}

#[derive(Deserialize, Validate)]
pub struct VerifyEmailRequest {
    #[serde(default)]
    #[validate(custom(function = "crate::utils::validator_utils::validate_required"))]
    pub token: String,
}

#[derive(Deserialize, Validate)]
pub struct ForgotPasswordRequest {
    #[serde(default)]
    #[validate(custom(function = "crate::utils::validator_utils::validate_required"))]
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
}

#[derive(Deserialize, Validate)]
pub struct ResetPasswordRequest {
    #[serde(default)]
    #[validate(custom(function = "crate::utils::validator_utils::validate_required"))]
    pub token: String,

    #[serde(default)]
    #[validate(custom(function = "crate::utils::validator_utils::validate_required"))]
    #[validate(length(min = 6, message = "Password must be at least 6 characters"))]
    pub new_password: String,
}

// --- MFA / 2FA Models ---

#[derive(Serialize)]
pub struct TwoFaSetupResponse {
    pub secret: String,
    pub qr_code_url: String, // Data URI base64
    pub backup_codes: Vec<String>,
}

#[derive(Deserialize, Validate)]
pub struct TwoFaConfirmRequest {
    #[serde(default)]
    #[validate(custom(function = "crate::utils::validator_utils::validate_required"))]
    pub code: String,
    
    #[serde(default)]
    #[validate(custom(function = "crate::utils::validator_utils::validate_required"))]
    pub secret: String,
}

#[derive(Deserialize, Validate)]
pub struct TwoFaLoginRequest {
    #[serde(default)]
    // Code is now optional because it could be a backup code passed here? 
    // Wait, let's keep it required as "code" field can carry TOTP OR Backup Code.
    #[validate(custom(function = "crate::utils::validator_utils::validate_required"))]
    pub code: String,
    
    #[serde(default)]
    #[validate(custom(function = "crate::utils::validator_utils::validate_required"))]
    pub temp_token: String,
}

#[derive(Serialize)]
pub struct TwoFaLoginRequiredResponse {
    pub temp_token: String,
}

#[derive(Deserialize, Validate)]
pub struct TwoFaDisableRequest {
    #[serde(default)]
    #[validate(custom(function = "crate::utils::validator_utils::validate_required"))]
    pub password: String,
}

#[derive(Serialize)]
pub struct SessionResponse {
    pub id: Uuid,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub device_type: Option<String>, // mobile, desktop, etc.
    pub last_activity: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub is_current: bool,
}

#[derive(Serialize)]
pub struct BackupCodesResponse {
    pub backup_codes: Vec<String>,
}
