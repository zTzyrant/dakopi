use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};
use axum::http::StatusCode;
use sea_orm::DatabaseConnection;
use jsonwebtoken::{encode, Header, EncodingKey};
use chrono::{Utc, Duration};
use uuid::Uuid;
use serde::{Deserialize, Serialize};

use crate::repositories::user_repository::UserRepository;
use crate::config::Config;
use crate::entities::user;

// Constants
pub struct AuthService;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,      // Subject (Public ID)
    pub username: String,
    pub exp: usize,     // Expired at
    pub iat: usize,     // Issued at
}

impl AuthService {
    // --- BUSINESS LOGIC ---

    pub async fn register_user(
        db: &DatabaseConnection,
        username: String,
        email: String,
        password: String,
    ) -> Result<user::Model, (StatusCode, &'static str, String)> {
        
        // 1. Check Duplicate
        let duplicates = UserRepository::find_active_duplicates(db, &username, &email)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Database error".to_string()))?;

        if !duplicates.is_empty() {
            let mut username_exists = false;
            let mut email_exists = false;

            for user in duplicates {
                if user.username == username {
                    username_exists = true;
                }
                if user.email == email {
                    email_exists = true;
                }
            }

            let message = if username_exists && email_exists {
                "Username and Email already exists"
            } else if username_exists {
                "Username already exists"
            } else {
                "Email already exists"
            };

            let error_code = if username_exists && email_exists {
                "AUTH_DUPLICATE"
            } else if username_exists {
                "AUTH_DUPLICATE_USERNAME"
            } else {
                "AUTH_DUPLICATE_EMAIL"
            };  

            return Err((StatusCode::CONFLICT, error_code, message.to_string()));
        }

        // 2. Hash Password
        let hashed_password = Self::hash_password(password)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "HASH_ERR", "Failed to hash password".to_string()))?;

        // 3. Save to Repo
        UserRepository::create(db, username, email, hashed_password)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_WRITE_ERR", "Failed to save user".to_string()))
    }

    pub async fn login_user(
        db: &DatabaseConnection,
        login_id: String,
        password: String
    ) -> Result<(String, String), (StatusCode, &'static str, String)> {
        
        // 1. Find User
        let user = UserRepository::find_active_by_login_id(db, &login_id)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Database error".to_string()))?
            .ok_or((StatusCode::UNAUTHORIZED, "AUTH_FAILED", "Invalid username or password".to_string()))?;

        // 2. Verify Password
        let is_valid = Self::verify_password(password, &user.password_hash)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "HASH_ERR", "Password verification failed".to_string()))?;

        if !is_valid {
            return Err((StatusCode::UNAUTHORIZED, "AUTH_FAILED", "Invalid username or password".to_string()));
        }

        // 3. Generate Token
        let token = Self::generate_jwt(user.public_id, &user.username)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "JWT_ERR", "Token generation failed".to_string()))?;

        Ok((token, "Bearer".to_string()))
    }

    // --- UTILS ---

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
        let config = Config::init();
        let now = Utc::now();
        let expire = now + Duration::minutes(config.jwt_expires_in);

        let claims = Claims {
            sub: user_id,
            username: username.to_string(),
            exp: expire.timestamp() as usize,
            iat: now.timestamp() as usize,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
        )
    }
}