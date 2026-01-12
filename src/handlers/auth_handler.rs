use axum::{
    extract::{State, Extension, Path, Query},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use validator::Validate;
use crate::config::AppState;
use crate::models::auth_model::{
    LoginRequest, LoginResponse, RegisterRequest, RegisterResponse, 
    ResetEmailLimitRequest, ProfileResponse,
    VerifyEmailRequest, ForgotPasswordRequest, ResetPasswordRequest,
    TwoFaConfirmRequest, TwoFaLoginRequest, TwoFaLoginRequiredResponse,
    TwoFaSetupResponse, TwoFaDisableRequest, SessionResponse, CurrentUser
};
use crate::services::auth_service::AuthService;
use crate::services::oauth_service::OAuthService;
use crate::utils::api_response::ResponseBuilder;
use crate::utils::validated_wrapper::ValidatedJson; 

// ... (handlers)

// 4. SESSION HANDLERS

pub async fn get_sessions_handler(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    match AuthService::get_user_sessions(&state.db, user.id, Some(user.session_id)).await {
        Ok(sessions) => ResponseBuilder::success("SESSIONS_FETCHED", "Active sessions", sessions).into_response(),
        Err((status, code, msg)) => ResponseBuilder::error::<Vec<SessionResponse>>(status, code, &msg).into_response(),
    }
}

pub async fn revoke_session_handler(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(session_id): Path<uuid::Uuid>,
) -> Response {
    match AuthService::revoke_session(&state.db, user.id, session_id).await {
        Ok(_) => ResponseBuilder::success::<()>("SESSION_REVOKED", "Session revoked successfully", ()).into_response(),
        Err((status, code, msg)) => ResponseBuilder::error::<()>(status, code, &msg).into_response(),
    }
}

pub async fn revoke_all_sessions_handler(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    match AuthService::revoke_all_sessions(&state.db, user.id).await {
        Ok(_) => ResponseBuilder::success::<()>("SESSIONS_REVOKED", "All sessions revoked successfully", ()).into_response(),
        Err((status, code, msg)) => ResponseBuilder::error::<()>(status, code, &msg).into_response(),
    }
}
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
) -> Response {
    let user_agent = headers.get("user-agent").and_then(|h| h.to_str().ok()).map(|s| s.to_string());
    let ip_address = headers.get("x-forwarded-for").and_then(|h| h.to_str().ok()).map(|s| s.to_string());

    match AuthService::login_user(
        &state,
        payload.login_id,
        payload.password,
        payload.remember_me,
        user_agent,
        ip_address
    ).await {
        Ok((token, token_exp, refresh_token, refresh_exp, type_, is_mfa_required)) => {
            if is_mfa_required {
                return ResponseBuilder::fail_with_data(
                    axum::http::StatusCode::ACCEPTED,
                    "TWO_FACTOR_REQUIRED",
                    "Two-factor authentication is required",
                    TwoFaLoginRequiredResponse { temp_token: token }
                ).into_response();
            }

            ResponseBuilder::success(
                "AUTH_LOGIN_SUCCESS",
                "Login successful",
                LoginResponse { 
                    token, 
                    token_expires_at: token_exp,
                    refresh_token, 
                    refresh_token_expires_at: refresh_exp,
                    type_ 
                }
            ).into_response()
        },
        Err((status, code, message)) => ResponseBuilder::error::<LoginResponse>(status, code, &message).into_response(),
    }
}

// 2.1 HANDLER SETUP 2FA
pub async fn setup_2fa_handler(
    State(state): State<AppState>,
    // TODO: Ambil user_id dari JWT middleware nantinya
) -> Response {
    // Simulasi ambil user pertama sementara middleware auth belum terpasang sempurna di handler ini
    use crate::entities::user::{Entity as User};
    use sea_orm::{EntityTrait, QueryOrder};

    let user = match User::find().order_by_asc(crate::entities::user::Column::Id).one(&state.db).await {
        Ok(Some(u)) => u,
        _ => return ResponseBuilder::error::<TwoFaSetupResponse>(axum::http::StatusCode::NOT_FOUND, "USER_NOT_FOUND", "User not found").into_response(),
    };

    match AuthService::generate_2fa_setup(&state.db, user.public_id).await {
        Ok(data) => ResponseBuilder::success("2FA_SETUP_READY", "Scan this QR code", data).into_response(),
        Err((status, code, msg)) => ResponseBuilder::error::<TwoFaSetupResponse>(status, code, &msg).into_response(),
    }
}

// 2.2 HANDLER CONFIRM 2FA
pub async fn confirm_2fa_handler(
    State(state): State<AppState>,
    ValidatedJson(payload): ValidatedJson<TwoFaConfirmRequest>,
) -> Response {
    // Simulasi ambil user pertama
    use crate::entities::user::{Entity as User};
    use sea_orm::{EntityTrait, QueryOrder};

    let user = match User::find().order_by_asc(crate::entities::user::Column::Id).one(&state.db).await {
        Ok(Some(u)) => u,
        _ => return ResponseBuilder::error::<()>(axum::http::StatusCode::NOT_FOUND, "USER_NOT_FOUND", "User not found").into_response(),
    };

    match AuthService::enable_2fa(&state.db, user.public_id, payload.secret, payload.code).await {
        Ok(data) => ResponseBuilder::success("2FA_ENABLED", "Two-factor authentication enabled. Backup codes generated.", data).into_response(),
        Err((status, code, msg)) => ResponseBuilder::error::<()>(status, code, &msg).into_response(),
    }
}

// 2.3 HANDLER VERIFY 2FA LOGIN
pub async fn verify_2fa_login_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    ValidatedJson(payload): ValidatedJson<TwoFaLoginRequest>,
) -> Response {
    let user_agent = headers.get("user-agent").and_then(|h| h.to_str().ok()).map(|s| s.to_string());
    let ip_address = headers.get("x-forwarded-for").and_then(|h| h.to_str().ok()).map(|s| s.to_string());

    match AuthService::verify_2fa_login(
        &state,
        payload.temp_token,
        payload.code,
        user_agent,
        ip_address
    ).await {
        Ok((token, token_exp, refresh_token, refresh_exp, type_)) => ResponseBuilder::success(
            "AUTH_LOGIN_SUCCESS",
            "MFA Login successful",
            LoginResponse { 
                token, 
                token_expires_at: token_exp,
                refresh_token, 
                refresh_token_expires_at: refresh_exp,
                type_ 
            }
        ).into_response(),
        Err((status, code, message)) => ResponseBuilder::error::<LoginResponse>(status, code, &message).into_response(),
    }
}

// 2.4 HANDLER DISABLE 2FA
pub async fn disable_2fa_handler(
    State(state): State<AppState>,
    ValidatedJson(payload): ValidatedJson<TwoFaDisableRequest>,
) -> Response {
    // Simulasi ambil user pertama
    use crate::entities::user::{Entity as User};
    use sea_orm::{EntityTrait, QueryOrder};

    let user = match User::find().order_by_asc(crate::entities::user::Column::Id).one(&state.db).await {
        Ok(Some(u)) => u,
        _ => return ResponseBuilder::error::<()>(axum::http::StatusCode::NOT_FOUND, "USER_NOT_FOUND", "User not found").into_response(),
    };

    match AuthService::disable_2fa(&state.db, user.public_id, payload.password).await {
        Ok(_) => ResponseBuilder::success::<()>("2FA_DISABLED", "Two-factor authentication disabled", ()).into_response(),
        Err((status, code, msg)) => ResponseBuilder::error::<()>(status, code, &msg).into_response(),
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
    Extension(current_user): Extension<CurrentUser>,
) -> impl IntoResponse {
    match AuthService::get_profile(&state.db, current_user.id).await {
        Ok(profile) => ResponseBuilder::success("PROFILE_FETCHED", "Success", profile),
        Err((status, code, msg)) => ResponseBuilder::error::<ProfileResponse>(status, code, &msg),
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
    headers: axum::http::HeaderMap,
    ValidatedJson(payload): ValidatedJson<RefreshTokenRequest>, 
) -> impl IntoResponse {
    let access_token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("")
        .to_string();

    match AuthService::logout_user(&state, access_token, payload.refresh_token).await {
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
        
        // 11. OAUTH HANDLERS
        
        #[derive(Deserialize)]
        pub struct OAuthCallbackParams {
            pub code: String,
            pub _state: Option<String>,
        }
        
        pub async fn get_oauth_url_handler(
            Path(provider): Path<String>,
        ) -> impl IntoResponse {
            match OAuthService::get_authorization_url(&provider) {
                Ok(url) => ResponseBuilder::success(
                    "OAUTH_URL_GENERATED",
                    "Redirect URL generated",
                    serde_json::json!({ "url": url })
                ),
                Err((status, code, msg)) => ResponseBuilder::error::<serde_json::Value>(status, code, &msg),
            }
        }
        
        pub async fn oauth_callback_handler(
            State(state): State<AppState>,
            headers: axum::http::HeaderMap,
            Path(provider): Path<String>,
            Query(params): Query<OAuthCallbackParams>,
        ) -> impl IntoResponse {
            let user_agent = headers.get("user-agent").and_then(|h| h.to_str().ok()).map(|s| s.to_string());
            let ip_address = headers.get("x-forwarded-for").and_then(|h| h.to_str().ok()).map(|s| s.to_string());
        
            match OAuthService::verify_and_link(
                &state,
                &provider,
                params.code,
                ip_address,
                user_agent
            ).await {
                Ok((token, token_exp, refresh_token, refresh_exp, type_)) => ResponseBuilder::success(
                    "AUTH_LOGIN_SUCCESS",
                    "Login successful via OAuth",
                    LoginResponse { 
                        token, 
                        token_expires_at: token_exp,
                        refresh_token, 
                        refresh_token_expires_at: refresh_exp,
                        type_ 
                    }
                ),
                Err((status, code, message)) => ResponseBuilder::error::<LoginResponse>(status, code, &message),
            }
        }
        
