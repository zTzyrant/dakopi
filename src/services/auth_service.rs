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

use crate::repositories::user_repository::UserRepository;
use crate::config::AppState;
use crate::entities::{user, role, user_role, session, email_verification_token, password_reset_token};
use crate::models::auth_model::{ProfileResponse, RoleInfo};
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
        db: &DatabaseConnection,
        login_id: String,
        password: String,
        user_agent: Option<String>,
        ip_address: Option<String>,
    ) -> Result<(String, Option<String>, String), (StatusCode, &'static str, String)> {
        let user = UserRepository::find_active_by_login_id(db, &login_id)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Database error".to_string()))?
            .ok_or((StatusCode::UNAUTHORIZED, "AUTH_FAILED", "Invalid username or password".to_string()))?;

        let is_valid = Self::verify_password(password, &user.password_hash)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "HASH_ERR", "Password verification failed".to_string()))?;

        if !is_valid {
            return Err((StatusCode::UNAUTHORIZED, "AUTH_FAILED", "Invalid username or password".to_string()));
        }

        // Generate Tokens
        let token = Self::generate_jwt(user.public_id, &user.username)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "JWT_ERR", "Token generation failed".to_string()))?;

        let (refresh_token, jti) = JwtUtils::generate_refresh_token(user.public_id, &user.username)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "JWT_ERR", "Refresh token generation failed".to_string()))?;

        // Create Session
        let session = session::ActiveModel {
            id: Set(Uuid::now_v7()),
            user_id: Set(user.id),
            refresh_token_jti: Set(jti),
            user_agent: Set(user_agent),
            ip_address: Set(ip_address),
            last_activity: Set(Utc::now()),
            expires_at: Set(Utc::now() + Duration::days(7)), // Match refresh token expiry
            created_at: Set(Utc::now()),
            revoked_at: Set(None),
            ..Default::default()
        };

        session.insert(db).await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, "SESSION_ERR", format!("Failed to create session: {}", e)))?;

        Ok((token, Some(refresh_token), "Bearer".to_string()))
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
        let new_access_token = Self::generate_jwt(claims.sub, &claims.username)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "JWT_ERR", "Token generation failed".to_string()))?;

        let (new_refresh_token, new_jti) = JwtUtils::generate_refresh_token(claims.sub, &claims.username)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "JWT_ERR", "Token generation failed".to_string()))?;

        // 4. Update Session (Rotate JTI)
        let mut session_active: session::ActiveModel = session.into();
        session_active.refresh_token_jti = Set(new_jti);
        session_active.last_activity = Set(Utc::now());
        session_active.expires_at = Set(Utc::now() + Duration::days(7));
        
        session_active.update(db).await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_WRITE_ERR", "Failed to update session".to_string()))?;

        Ok((new_access_token, new_refresh_token))
    }

    pub async fn logout_user(
        db: &DatabaseConnection,
        token: String
    ) -> Result<(), (StatusCode, &'static str, String)> {
        // Try to decode token (either access or refresh) to get JTI if possible, 
        // OR simply blacklist the token if it's an access token.
        // For 'BetterAuth' standard, we usually revoke the session linked to the Refresh Token JTI.
        
        // Scenario: Client sends Access Token. Access Token usually doesn't have JTI in our simple impl (only Refresh has).
        // If client sends Refresh Token to logout, we revoke session.
        
        let claims = JwtUtils::validate_refresh_token(&token)
            .map_err(|_| (StatusCode::BAD_REQUEST, "INVALID_TOKEN", "Invalid token".to_string()))?;

        let session = session::Entity::find()
            .filter(session::Column::RefreshTokenJti.eq(&claims.jti))
            .one(db)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Database error".to_string()))?;

        if let Some(session) = session {
            let mut session_active: session::ActiveModel = session.into();
            session_active.revoked_at = Set(Some(Utc::now()));
            session_active.update(db).await
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_WRITE_ERR", "Failed to revoke session".to_string()))?;
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

    fn generate_jwt(user_id: Uuid, username: &str) -> Result<String, jsonwebtoken::errors::Error> {
        JwtUtils::generate_jwt(user_id, username)
    }
}