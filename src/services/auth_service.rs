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

use crate::repositories::user_repository::UserRepository;
use crate::config::AppState;
use crate::entities::{user, role, user_role};
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

        txn.commit().await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "TXN_COMMIT_ERR", "Failed to commit transaction".to_string()))?;

        Ok(user)
    }

    pub async fn login_user(
        db: &DatabaseConnection,
        login_id: String,
        password: String
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

        let token = Self::generate_jwt(user.public_id, &user.username)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "JWT_ERR", "Token generation failed".to_string()))?;

        let refresh_token = JwtUtils::generate_refresh_token(user.public_id, &user.username)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "JWT_ERR", "Refresh token generation failed".to_string()))?;

        Ok((token, Some(refresh_token), "Bearer".to_string()))
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