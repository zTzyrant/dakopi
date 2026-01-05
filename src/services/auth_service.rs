use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};
use casbin::{MgmtApi};
use axum::http::StatusCode;
use sea_orm::{DatabaseConnection, EntityTrait, QueryFilter, ColumnTrait, ActiveValue::Set, TransactionTrait, ActiveModelTrait};
use uuid::Uuid;
use chrono::{Utc, Duration};
use totp_rs::{Algorithm, TOTP, Secret};
use rand_core::RngCore;
use crate::config::Config;

use crate::repositories::user_repository::UserRepository;
use crate::config::AppState;
use crate::entities::{user, role, user_role, session, email_verification_token, password_reset_token};
use crate::models::auth_model::{ProfileResponse, RoleInfo, TwoFaSetupResponse, SessionResponse};
use crate::utils::jwt_utils::JwtUtils;

pub struct AuthService;

impl AuthService {
    pub async fn get_profile(
        db: &DatabaseConnection,
        user_id: Uuid,
    ) -> Result<ProfileResponse, (StatusCode, &'static str, String)> {
        let result = UserRepository::find_by_public_id_with_roles(db, user_id)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Database error".to_string()))?
            .ok_or((StatusCode::NOT_FOUND, "USER_NOT_FOUND", "User not found".to_string()))?;

        let (user, roles) = result;

        Ok(ProfileResponse {
            id: user.public_id,
            username: user.username,
            email: user.email,
            roles: roles.into_iter().map(|r| RoleInfo {
                id: r.public_id,
                name: r.name,
            }).collect(),
        })
    }

    pub async fn register_user(
        state: &AppState,
        username: String,
        email: String,
        password: String,
    ) -> Result<user::Model, (StatusCode, &'static str, String)> {
        let db = &state.db;
        
        // 1. Check Duplicate
        let duplicates = UserRepository::find_active_duplicates(db, &username, &email)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Database error".to_string()))?;

        if !duplicates.is_empty() {
            return Err(Self::handle_duplicate_error(duplicates, username, email));
        }

        // 2. Hash Password
        let hashed_password = Self::hash_password(password)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "HASH_ERR", "Failed to hash password".to_string()))?;

        // 3. Start Transaction
        let txn = db.begin().await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "TXN_ERR", "Failed to start transaction".to_string()))?;

        // 4. Save User
        let user = UserRepository::create(&txn, username.clone(), email.clone(), hashed_password)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_WRITE_ERR", "Failed to save user".to_string()))?;

        // 5. Assign "user" role
        let role_user = role::Entity::find()
            .filter(role::Column::Name.eq("user"))
            .one(&txn)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "ROLE_ERR", "Database error finding role".to_string()))?
            .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "ROLE_NOT_FOUND", "Default role 'user' not found. Please run seeders.".to_string()))?;

        let user_role_link = user_role::ActiveModel {
            user_id: Set(user.id),
            role_id: Set(role_user.id),
        };
        
        user_role_link.insert(&txn).await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "ROLE_ASSIGN_ERR", "Failed to assign role".to_string()))?;

        // 6. Add to Casbin grouping
        {
            let mut enforcer = state.enforcer.write().await;
            let _: bool = enforcer.add_grouping_policy(vec![user.public_id.to_string(), "user".to_string()]).await
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "CASBIN_ERR", "Failed to add security policy".to_string()))?;
        }

        // 7. Create Email Verification Token
        let verification_token = Uuid::new_v4().to_string(); // Random token
        let email_token = email_verification_token::ActiveModel {
            id: Set(Uuid::now_v7()),
            user_id: Set(user.id),
            token: Set(verification_token),
            email: Set(user.email.clone()),
            expires_at: Set(Utc::now() + Duration::days(1)),
            used_at: Set(None),
            created_at: Set(Utc::now()),
        };
        
        email_token.insert(&txn).await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "VERIFICATION_ERR", "Failed to create verification token".to_string()))?;

        txn.commit().await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "TXN_COMMIT_ERR", "Failed to commit transaction".to_string()))?;

        // TODO: Send email asynchronously here (requires background job or fire-and-forget)

        Ok(user)
    }

    pub async fn login_user(
        state: &AppState,
        login_id: String,
        password: String,
        remember_me: bool,
        user_agent: Option<String>,
        ip_address: Option<String>,
    ) -> Result<(String, usize, Option<String>, Option<usize>, String, bool), (StatusCode, &'static str, String)> {
        let db = &state.db;

        let user = UserRepository::find_active_by_login_id(db, &login_id)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Database error".to_string()))?
            .ok_or((StatusCode::UNAUTHORIZED, "AUTH_FAILED", "Invalid username or password".to_string()))?;

        let is_valid = Self::verify_password(password, &user.password_hash)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "HASH_ERR", "Password verification failed".to_string()))?;

        if !is_valid {
            return Err((StatusCode::UNAUTHORIZED, "AUTH_FAILED", "Invalid username or password".to_string()));
        }

        // Check if 2FA is enabled
        if user.two_factor_enabled.unwrap_or(false) {
            let temp_token = JwtUtils::generate_2fa_temp_token(user.public_id)
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "JWT_ERR", "Token generation failed".to_string()))?;
            
            // Return temp_token and flag that 2FA is required
            return Ok((temp_token, 0, None, None, "2FA_REQUIRED".to_string(), true));
        }

        // Generate Access Token
        let (token, token_exp, _) = JwtUtils::generate_jwt(user.public_id)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "JWT_ERR", "Token generation failed".to_string()))?;

        // Generate Refresh Token
        let cfg = Config::init();
        let refresh_days = if remember_me { cfg.jwt_remember_days } else { cfg.jwt_refresh_days };
        
        let (refresh_token, jti, refresh_exp) = JwtUtils::generate_refresh_token(user.public_id, refresh_days)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "JWT_ERR", "Refresh token generation failed".to_string()))?;

        // Create Session
        let session = session::ActiveModel {
            id: Set(Uuid::now_v7()),
            user_id: Set(user.id),
            refresh_token_jti: Set(jti),
            user_agent: Set(user_agent),
            ip_address: Set(ip_address),
            last_activity: Set(Utc::now()),
            expires_at: Set(Utc::now() + Duration::days(refresh_days)), 
            created_at: Set(Utc::now()),
            revoked_at: Set(None),
            ..Default::default()
        };

        session.insert(db).await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, "SESSION_ERR", format!("Failed to create session: {}", e)))?;

        Ok((token, token_exp, Some(refresh_token), Some(refresh_exp), "Bearer".to_string(), false))
    }

    pub async fn generate_2fa_setup(
        db: &DatabaseConnection,
        user_id: Uuid,
    ) -> Result<TwoFaSetupResponse, (StatusCode, &'static str, String)> {
        let user = user::Entity::find()
            .filter(user::Column::PublicId.eq(user_id))
            .one(db)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Database error".to_string()))?
            .ok_or((StatusCode::NOT_FOUND, "USER_NOT_FOUND", "User not found".to_string()))?;

        // Generate Random Secret (20 bytes for SHA1)
        let mut secret_bytes = [0u8; 20];
        rand_core::OsRng.fill_bytes(&mut secret_bytes);
        
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret_bytes.to_vec(),
            Some("Dakopi".to_string()),
            user.email.clone(),

        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, "TOTP_ERR", format!("Failed to generate TOTP: {}", e)))?;

        let secret = totp.get_secret_base32();
        let qr_code_url = totp.get_qr_base64().map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "QR_ERR", "Failed to generate QR code".to_string()))?;

        Ok(TwoFaSetupResponse {
            secret,
            qr_code_url,
        })
    }

    pub async fn enable_2fa(
        db: &DatabaseConnection,
        user_id: Uuid,
        secret: String,
        code: String,
    ) -> Result<(), (StatusCode, &'static str, String)> {
        let user = user::Entity::find()
            .filter(user::Column::PublicId.eq(user_id))
            .one(db)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Database error".to_string()))?
            .ok_or((StatusCode::NOT_FOUND, "USER_NOT_FOUND", "User not found".to_string()))?;

        // Decode Secret (Base32 -> Bytes)
        let secret_bytes = Secret::Encoded(secret.clone())
            .to_bytes()
            .map_err(|_| (StatusCode::BAD_REQUEST, "INVALID_SECRET", "Invalid secret format".to_string()))?;

        // Verify Code
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret_bytes,
            Some("Dakopi".to_string()),
            user.email.clone(),
        ).map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "TOTP_ERR", "Failed to initialize TOTP".to_string()))?;

        if !totp.check_current(&code).map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "TOTP_CHECK_ERR", "Failed to check code".to_string()))? {
            return Err((StatusCode::BAD_REQUEST, "INVALID_CODE", "Invalid verification code".to_string()));
        }

        // Update User
        let mut user_active: user::ActiveModel = user.into();
        user_active.two_factor_enabled = Set(Some(true));
        user_active.two_factor_secret = Set(Some(secret));
        user_active.update(db).await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_WRITE_ERR", "Failed to update user 2FA status".to_string()))?;

        Ok(())
    }

    pub async fn verify_2fa_login(
        db: &DatabaseConnection,
        temp_token: String,
        code: String,
        user_agent: Option<String>,
        ip_address: Option<String>,
    ) -> Result<(String, usize, Option<String>, Option<usize>, String), (StatusCode, &'static str, String)> {
        // 1. Validate Temp Token
        let claims = JwtUtils::validate_2fa_temp_token(&temp_token)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "INVALID_TEMP_TOKEN", "Temporary token invalid or expired".to_string()))?;

        // 2. Find User
        let user = user::Entity::find()
            .filter(user::Column::PublicId.eq(claims.sub))
            .one(db)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Database error".to_string()))?
            .ok_or((StatusCode::NOT_FOUND, "USER_NOT_FOUND", "User not found".to_string()))?;

        let secret = user.two_factor_secret.as_ref()
            .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "MFA_NOT_CONFIGURED", "MFA is not configured for this user".to_string()))?;

        // Decode Secret (Base32 -> Bytes)
        let secret_bytes = Secret::Encoded(secret.clone())
            .to_bytes()
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "INVALID_STORED_SECRET", "Stored secret is invalid".to_string()))?;

        // 3. Verify TOTP Code
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret_bytes,
            Some("Dakopi".to_string()),
            user.email.clone(),
        ).map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "TOTP_ERR", "Failed to initialize TOTP".to_string()))?;

        if !totp.check_current(&code).map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "TOTP_CHECK_ERR", "Failed to check code".to_string()))? {
            return Err((StatusCode::BAD_REQUEST, "INVALID_CODE", "Invalid MFA code".to_string()));
        }

        // 4. Generate Final Tokens
        let (token, token_exp, _) = JwtUtils::generate_jwt(user.public_id)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "JWT_ERR", "Token generation failed".to_string()))?;

        let cfg = Config::init();
        let (refresh_token, jti, refresh_exp) = JwtUtils::generate_refresh_token(user.public_id, cfg.jwt_refresh_days)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "JWT_ERR", "Refresh token generation failed".to_string()))?;

        // 5. Create Session
        let session = session::ActiveModel {
            id: Set(Uuid::now_v7()),
            user_id: Set(user.id),
            refresh_token_jti: Set(jti),
            user_agent: Set(user_agent),
            ip_address: Set(ip_address),
            last_activity: Set(Utc::now()),
            expires_at: Set(Utc::now() + Duration::days(cfg.jwt_refresh_days)),
            created_at: Set(Utc::now()),
            revoked_at: Set(None),
            ..Default::default()
        };

        session.insert(db).await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, "SESSION_ERR", format!("Failed to create session: {}", e)))?;

        Ok((token, token_exp, Some(refresh_token), Some(refresh_exp), "Bearer".to_string()))
    }

    pub async fn disable_2fa(
        db: &DatabaseConnection,
        user_id: Uuid,
        password: String,
    ) -> Result<(), (StatusCode, &'static str, String)> {
        let user = user::Entity::find()
            .filter(user::Column::PublicId.eq(user_id))
            .one(db)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Database error".to_string()))?
            .ok_or((StatusCode::NOT_FOUND, "USER_NOT_FOUND", "User not found".to_string()))?;

        // Verify Password first
        let is_valid = Self::verify_password(password, &user.password_hash)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "HASH_ERR", "Password verification failed".to_string()))?;

        if !is_valid {
            return Err((StatusCode::UNAUTHORIZED, "INVALID_PASSWORD", "Invalid password".to_string()));
        }

        // Update User
        let mut user_active: user::ActiveModel = user.into();
        user_active.two_factor_enabled = Set(Some(false));
        user_active.two_factor_secret = Set(None);
        user_active.update(db).await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_WRITE_ERR", "Failed to disable 2FA".to_string()))?;

        Ok(())
    }

    pub async fn get_user_sessions(
        db: &DatabaseConnection,
        user_id: Uuid,
        current_jti: Option<String>,
    ) -> Result<Vec<SessionResponse>, (StatusCode, &'static str, String)> {
        // Find DB ID for user
        let user = user::Entity::find()
             .filter(user::Column::PublicId.eq(user_id))
             .one(db)
             .await
             .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Database error".to_string()))?
             .ok_or((StatusCode::NOT_FOUND, "USER_NOT_FOUND", "User not found".to_string()))?;

        let sessions = session::Entity::find()
            .filter(session::Column::UserId.eq(user.id))
            .filter(session::Column::RevokedAt.is_null())
            .filter(session::Column::ExpiresAt.gt(Utc::now()))
            .all(db)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Database error finding sessions".to_string()))?;

        let response = sessions.into_iter().map(|s| SessionResponse {
            id: s.id,
            user_agent: s.user_agent,
            ip_address: s.ip_address,
            device_type: s.device_type,
            last_activity: s.last_activity,
            created_at: s.created_at,
            is_current: current_jti.as_ref().map(|jti| jti == &s.refresh_token_jti).unwrap_or(false),
        }).collect();

        Ok(response)
    }

    pub async fn revoke_session(
        db: &DatabaseConnection,
        user_id: Uuid,
        session_id: Uuid,
    ) -> Result<(), (StatusCode, &'static str, String)> {
         // Find DB ID for user first
        let user = user::Entity::find()
             .filter(user::Column::PublicId.eq(user_id))
             .one(db)
             .await
             .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Database error".to_string()))?
             .ok_or((StatusCode::NOT_FOUND, "USER_NOT_FOUND", "User not found".to_string()))?;

        let session = session::Entity::find_by_id(session_id)
            .filter(session::Column::UserId.eq(user.id))
            .one(db)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Database error".to_string()))?
            .ok_or((StatusCode::NOT_FOUND, "SESSION_NOT_FOUND", "Session not found or not owned by user".to_string()))?;

        let mut session_active: session::ActiveModel = session.into();
        session_active.revoked_at = Set(Some(Utc::now()));
        session_active.update(db).await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_WRITE_ERR", "Failed to revoke session".to_string()))?;

        Ok(())
    }

    pub async fn revoke_all_sessions(
        db: &DatabaseConnection,
        user_id: Uuid,
    ) -> Result<(), (StatusCode, &'static str, String)> {
         let user = user::Entity::find()
             .filter(user::Column::PublicId.eq(user_id))
             .one(db)
             .await
             .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Database error".to_string()))?
             .ok_or((StatusCode::NOT_FOUND, "USER_NOT_FOUND", "User not found".to_string()))?;

        use sea_orm::sea_query::Expr;

        session::Entity::update_many()
            .col_expr(session::Column::RevokedAt, Expr::value(Utc::now()))
            .filter(session::Column::UserId.eq(user.id))
            .filter(session::Column::RevokedAt.is_null())
            .exec(db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, "DB_WRITE_ERR", format!("Failed to revoke sessions: {}", e)))?;

        Ok(())
    }

    pub async fn refresh_token(
        db: &DatabaseConnection,
        token: String
    ) -> Result<(String, String), (StatusCode, &'static str, String)> {
        // 1. Validate Token Signature
        let claims = JwtUtils::validate_refresh_token(&token)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "INVALID_TOKEN", "Invalid refresh token".to_string()))?;

        // 2. Check Session in DB
        let session = session::Entity::find()
            .filter(session::Column::RefreshTokenJti.eq(&claims.jti))
            .one(db)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Database error".to_string()))?
            .ok_or((StatusCode::UNAUTHORIZED, "SESSION_NOT_FOUND", "Session not found or revoked".to_string()))?;

        if session.revoked_at.is_some() {
             return Err((StatusCode::UNAUTHORIZED, "SESSION_REVOKED", "Session has been revoked".to_string()));
        }
        
        // 3. Generate New Tokens
        // Access token
        let (new_access_token, _, _) = JwtUtils::generate_jwt(claims.sub)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "JWT_ERR", "Token generation failed".to_string()))?;

        // Refresh token (maintain existing duration/type? For now default 7 days again or same as original config)
        // Ideally we check if it was "remember me" session, but for now we reset to default or use session duration
        // Let's use Config default
        let cfg = Config::init();
        let (new_refresh_token, new_jti, _) = JwtUtils::generate_refresh_token(claims.sub, cfg.jwt_refresh_days)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "JWT_ERR", "Token generation failed".to_string()))?;

        // 4. Update Session (Rotate JTI)
        let mut session_active: session::ActiveModel = session.into();
        session_active.refresh_token_jti = Set(new_jti);
        session_active.last_activity = Set(Utc::now());
        session_active.expires_at = Set(Utc::now() + Duration::days(cfg.jwt_refresh_days));
        
        session_active.update(db).await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_WRITE_ERR", "Failed to update session".to_string()))?;

        Ok((new_access_token, new_refresh_token))
    }

    pub async fn logout_user(
        state: &AppState,
        access_token: String,
        refresh_token: String
    ) -> Result<(), (StatusCode, &'static str, String)> {
        // 1. Blacklist Access Token (Redis)
        if let Ok(token_data) = JwtUtils::validate_jwt(&access_token) {
             let claims = token_data.claims;
             let now = Utc::now().timestamp() as usize;
             
             if claims.exp > now {
                 let ttl = claims.exp - now;
                 let key = format!("blacklist:token:{}", claims.jti);
                 // We store "revoked" string. RedisService::set serializes it to "\"revoked\"", which is fine.
                 let _ = state.redis_service.set(&key, "revoked", ttl as u64).await;
             }
        }

        // 2. Revoke Refresh Token Session (DB)
        if !refresh_token.is_empty() {
             if let Ok(claims) = JwtUtils::validate_refresh_token(&refresh_token) {
                let session = session::Entity::find()
                    .filter(session::Column::RefreshTokenJti.eq(&claims.jti))
                    .one(&state.db)
                    .await
                    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Database error".to_string()))?;

                if let Some(session) = session {
                    let mut session_active: session::ActiveModel = session.into();
                    session_active.revoked_at = Set(Some(Utc::now()));
                    session_active.update(&state.db).await
                        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_WRITE_ERR", "Failed to revoke session".to_string()))?;
                }
             }
        }

        Ok(())
    }

    pub async fn verify_email(
        db: &DatabaseConnection,
        token: String
    ) -> Result<(), (StatusCode, &'static str, String)> {
        let email_token = email_verification_token::Entity::find()
            .filter(email_verification_token::Column::Token.eq(&token))
            .one(db)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Database error".to_string()))?
            .ok_or((StatusCode::BAD_REQUEST, "INVALID_TOKEN", "Invalid verification token".to_string()))?;

        if email_token.expires_at < Utc::now() {
            return Err((StatusCode::BAD_REQUEST, "TOKEN_EXPIRED", "Verification token expired".to_string()));
        }
        
        if email_token.used_at.is_some() {
             return Err((StatusCode::BAD_REQUEST, "TOKEN_USED", "Token already used".to_string()));
        }

        // Update User
        let user = user::Entity::find_by_id(email_token.user_id)
            .one(db)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Database error".to_string()))?
            .ok_or((StatusCode::NOT_FOUND, "USER_NOT_FOUND", "User not found".to_string()))?;

        let mut user_active: user::ActiveModel = user.into();
        user_active.email_verified = Set(Some(true));
        user_active.email_verified_at = Set(Some(Utc::now()));
        user_active.update(db).await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_WRITE_ERR", "Failed to update user".to_string()))?;

        // Mark Token Used
        let mut token_active: email_verification_token::ActiveModel = email_token.into();
        token_active.used_at = Set(Some(Utc::now()));
        token_active.update(db).await
             .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_WRITE_ERR", "Failed to update token".to_string()))?;

        Ok(())
    }

    pub async fn request_password_reset(
        state: &AppState,
        email: String
    ) -> Result<(), (StatusCode, &'static str, String)> {
        let db = &state.db;
        let user = user::Entity::find()
            .filter(user::Column::Email.eq(&email))
            .one(db)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Database error".to_string()))?
            .ok_or((StatusCode::NOT_FOUND, "USER_NOT_FOUND", "User not found".to_string()))?;

        // Generate Token
        let reset_token = Uuid::new_v4().to_string();
        let expiry = Utc::now() + Duration::minutes(30);

        let token_model = password_reset_token::ActiveModel {
            id: Set(Uuid::now_v7()),
            user_id: Set(user.id),
            token: Set(reset_token.clone()),
            expires_at: Set(expiry),
            used_at: Set(None),
            created_at: Set(Utc::now()),
        };

        token_model.insert(db).await
             .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_WRITE_ERR", "Failed to create reset token".to_string()))?;

        // Send Email (Fire and forget)
        let _email_service = state.email_service.clone();
        tokio::spawn(async move {
             // In real app, create a send_reset_password_email method
             // For now we reuse welcome or just log it
             tracing::info!("Reset Token for {}: {}", email, reset_token);
             // TODO: Implement actual email sending for reset password
        });

        Ok(())
    }

    pub async fn reset_password(
        db: &DatabaseConnection,
        token: String,
        new_password: String
    ) -> Result<(), (StatusCode, &'static str, String)> {
        let reset_token = password_reset_token::Entity::find()
            .filter(password_reset_token::Column::Token.eq(&token))
            .one(db)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Database error".to_string()))?
            .ok_or((StatusCode::BAD_REQUEST, "INVALID_TOKEN", "Invalid reset token".to_string()))?;

         if reset_token.expires_at < Utc::now() {
            return Err((StatusCode::BAD_REQUEST, "TOKEN_EXPIRED", "Reset token expired".to_string()));
        }
        
        if reset_token.used_at.is_some() {
             return Err((StatusCode::BAD_REQUEST, "TOKEN_USED", "Token already used".to_string()));
        }

        // Hash New Password
        let hashed_password = Self::hash_password(new_password)
             .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "HASH_ERR", "Failed to hash password".to_string()))?;

        // Update User
        let user = user::Entity::find_by_id(reset_token.user_id)
            .one(db)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Database error".to_string()))?
            .ok_or((StatusCode::NOT_FOUND, "USER_NOT_FOUND", "User not found".to_string()))?;

        let mut user_active: user::ActiveModel = user.into();
        user_active.password_hash = Set(hashed_password);
        user_active.update(db).await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_WRITE_ERR", "Failed to update password".to_string()))?;

         // Mark Token Used
        let mut token_active: password_reset_token::ActiveModel = reset_token.into();
        token_active.used_at = Set(Some(Utc::now()));
        token_active.update(db).await
             .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_WRITE_ERR", "Failed to update token".to_string()))?;

        Ok(())
    }

    // --- UTILS ---

    fn handle_duplicate_error(duplicates: Vec<user::Model>, username: String, email: String) -> (StatusCode, &'static str, String) {
        let mut u_exists = false;
        let mut e_exists = false;
        for u in duplicates {
            if u.username == username { u_exists = true; }
            if u.email == email { e_exists = true; }
        }
        let (code, msg) = if u_exists && e_exists { ("AUTH_DUPLICATE", "Username and Email already exists") }
            else if u_exists { ("AUTH_DUPLICATE_USERNAME", "Username already exists") }
            else { ("AUTH_DUPLICATE_EMAIL", "Email already exists") };
        (StatusCode::CONFLICT, code, msg.to_string())
    }

        fn hash_password(password: String) -> Result<String, argon2::password_hash::Error> {

            let salt = SaltString::generate(&mut OsRng);

            let argon2 = Argon2::default();

            Ok(argon2.hash_password(password.as_bytes(), &salt)?.to_string())

        }

    

        fn verify_password(password: String, hash: &str) -> Result<bool, argon2::password_hash::Error> {

            let parsed_hash = PasswordHash::new(hash)?;

            Ok(Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok())

        }

    }

    