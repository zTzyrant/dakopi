use axum::{
    extract::State,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use validator::Validate;
use crate::config::AppState;
use crate::models::auth_model::{
    LoginRequest, LoginResponse, RegisterRequest, RegisterResponse, 
    ResetEmailLimitRequest, ProfileResponse,
    VerifyEmailRequest, ForgotPasswordRequest, ResetPasswordRequest
};
use crate::services::auth_service::AuthService;
use crate::utils::api_response::ResponseBuilder;
use crate::utils::validated_wrapper::ValidatedJson; 

// 1. HANDLER REGISTER
pub async fn register_user_handler(
    State(state): State<AppState>,
    ValidatedJson(payload): ValidatedJson<RegisterRequest>,
) -> impl IntoResponse {
    match AuthService::register_user(
        &state, 
        payload.username.clone(), 
        payload.email.clone(), 
        payload.password
    ).await {
        Ok(user) => {
            let email_service = state.email_service.clone();
            let email_to = user.email.clone();
            let username = user.username.clone();
            
            tokio::spawn(async move {
                if let Err(e) = email_service.send_welcome_email(&email_to, &username).await {
                    tracing::error!("Gagal mengirim email welcome: {}", e);
                }
            });

            ResponseBuilder::created(
                "AUTH_REGISTER_SUCCESS",
                "User registered successfully",
                RegisterResponse {
                    id: user.public_id,
                    username: user.username,
                    email: user.email,
                }
            )
        },
        Err((status, code, message)) => ResponseBuilder::error::<RegisterResponse>(status, code, &message),
    }
}

// 2. HANDLER LOGIN
pub async fn login_user_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    ValidatedJson(payload): ValidatedJson<LoginRequest>,
) -> impl IntoResponse {
    let user_agent = headers.get("user-agent").and_then(|h| h.to_str().ok()).map(|s| s.to_string());
    let ip_address = headers.get("x-forwarded-for").and_then(|h| h.to_str().ok()).map(|s| s.to_string());

    match AuthService::login_user(
        &state.db,
        payload.login_id,
        payload.password,
        user_agent,
        ip_address
    ).await {
        Ok((token, refresh_token, type_)) => ResponseBuilder::success(
            "AUTH_LOGIN_SUCCESS",
            "Login successful",
            LoginResponse { token, refresh_token, type_ }
        ),
        Err((status, code, message)) => ResponseBuilder::error::<LoginResponse>(status, code, &message),
    }
}

// 3. HANDLER RESET EMAIL LIMIT
pub async fn reset_email_limit_handler(
    State(state): State<AppState>,
    ValidatedJson(payload): ValidatedJson<ResetEmailLimitRequest>,
) -> impl IntoResponse {
    match state.email_service.reset_limit(&payload.secret).await {
        Ok(new_limit) => ResponseBuilder::success(
            "EMAIL_LIMIT_RESET",
            &format!("Email limit increased. New limit: {}", new_limit),
            serde_json::json!({ "new_limit": new_limit })
        ),
        Err(e) => ResponseBuilder::error::<serde_json::Value>(
            axum::http::StatusCode::BAD_REQUEST,
            "EMAIL_LIMIT_ERROR",
            &e
        ),
    }
}

// 4. HANDLER GET ROLES
pub async fn get_roles_handler(
    State(state): State<AppState>,
) -> impl IntoResponse {
    use crate::entities::role::{Entity as Role};
    use sea_orm::EntityTrait;

    match Role::find().all(&state.db).await {
        Ok(roles) => ResponseBuilder::success(
            "ROLES_FETCHED",
            "Successfully fetched all roles",
            roles
        ),
        Err(e) => ResponseBuilder::error(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "DB_ERR",
            &e.to_string()
        ),
    }
}

// 5. HANDLER PROFILE
pub async fn profile_handler(
    State(state): State<AppState>,
) -> impl IntoResponse {
    // TODO: Nantinya ambil ID dari JWT Extension. 
    // Untuk simulasi testing, kita coba ambil user pertama yang ada di DB.
    use crate::entities::user::{Entity as User};
    use sea_orm::{EntityTrait, QueryOrder};

    let first_user = User::find()
        .order_by_asc(crate::entities::user::Column::Id)
        .one(&state.db)
        .await
        .ok();

    if let Some(Some(u)) = first_user {
        match AuthService::get_profile(&state.db, u.public_id).await {
            Ok(profile) => ResponseBuilder::success("PROFILE_FETCHED", "Success", profile),
            Err((status, code, msg)) => ResponseBuilder::error::<ProfileResponse>(status, code, &msg),
        }
    } else {
        ResponseBuilder::error::<ProfileResponse>(
            axum::http::StatusCode::NOT_FOUND,
            "USER_NOT_FOUND",
            "No user found in database"
        )
    }
}

// 6. HANDLER REFRESH TOKEN

#[derive(Deserialize, Validate)]
pub struct RefreshTokenRequest {
    #[serde(default)]
    #[validate(custom(function = "crate::utils::validator_utils::validate_required"))]
    pub refresh_token: String,
}

#[derive(Serialize)]
pub struct RefreshTokenResponse {
    pub token: String,
    pub refresh_token: Option<String>,
    pub type_: String,
}

pub async fn refresh_token_handler(
    State(state): State<AppState>,
    ValidatedJson(payload): ValidatedJson<RefreshTokenRequest>,
) -> impl IntoResponse {
    match AuthService::refresh_token(&state.db, payload.refresh_token).await {
        Ok((token, refresh_token)) => ResponseBuilder::success(
            "TOKEN_REFRESHED",
            "Token refreshed successfully",
            RefreshTokenResponse {
                token,
                refresh_token: Some(refresh_token),
                type_: "Bearer".to_string(),
            }
        ),
        Err((status, code, message)) => ResponseBuilder::error::<RefreshTokenResponse>(status, code, &message),
    }
}

// 7. HANDLER LOGOUT
pub async fn logout_handler(
    State(state): State<AppState>,
    ValidatedJson(payload): ValidatedJson<RefreshTokenRequest>, 
) -> impl IntoResponse {
    match AuthService::logout_user(&state.db, payload.refresh_token).await {
        Ok(_) => ResponseBuilder::success::<()>(
            "LOGOUT_SUCCESS",
            "Successfully logged out",
            ()
        ),
        Err((status, code, msg)) => ResponseBuilder::error::<()>(status, code, &msg),
    }
}

// 8. HANDLER VERIFY EMAIL
pub async fn verify_email_handler(
    State(state): State<AppState>,
    ValidatedJson(payload): ValidatedJson<VerifyEmailRequest>,
) -> impl IntoResponse {
    match AuthService::verify_email(&state.db, payload.token).await {
        Ok(_) => ResponseBuilder::success::<()>(
            "EMAIL_VERIFIED",
            "Email verified successfully",
            ()
        ),
        Err((status, code, msg)) => ResponseBuilder::error::<()>(status, code, &msg),
    }
}

// 9. HANDLER FORGOT PASSWORD
pub async fn forgot_password_handler(
    State(state): State<AppState>,
    ValidatedJson(payload): ValidatedJson<ForgotPasswordRequest>,
) -> impl IntoResponse {
    match AuthService::request_password_reset(&state, payload.email).await {
        Ok(_) => ResponseBuilder::success::<()>(
            "RESET_EMAIL_SENT",
            "If the email exists, a reset link has been sent",
            ()
        ),
        Err((status, code, msg)) => ResponseBuilder::error::<()>(status, code, &msg),
    }
}

// 10. HANDLER RESET PASSWORD
pub async fn reset_password_handler(
    State(state): State<AppState>,
    ValidatedJson(payload): ValidatedJson<ResetPasswordRequest>,
) -> impl IntoResponse {
    match AuthService::reset_password(&state.db, payload.token, payload.new_password).await {
        Ok(_) => ResponseBuilder::success::<()>(
            "PASSWORD_RESET_SUCCESS",
            "Password has been reset successfully",
            ()
        ),
        Err((status, code, msg)) => ResponseBuilder::error::<()>(status, code, &msg),
    }
}
