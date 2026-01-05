use crate::config::Config;
use crate::models::auth_model::Claims;
use chrono::{Utc, Duration};
use jsonwebtoken::{encode, decode, DecodingKey, Validation, Header, EncodingKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    pub sub: Uuid,
    pub username: String,
    pub exp: usize,
    pub iat: usize,
    pub token_type: String, // To distinguish from access tokens
}

pub struct JwtUtils;

impl JwtUtils {
    /// Generate a JWT token with the provided user ID and username
    pub fn generate_jwt(user_id: Uuid, username: &str) -> Result<String, jsonwebtoken::errors::Error> {
        let cfg = Config::init();
        let now = Utc::now();
        let expire = now + Duration::minutes(cfg.jwt_expires_in);
        let claims = Claims {
            sub: user_id,
            username: username.to_string(),
            exp: expire.timestamp() as usize,
            iat: now.timestamp() as usize,
        };
        encode(&Header::default(), &claims, &EncodingKey::from_secret(cfg.jwt_secret.as_bytes()))
    }

    /// Validate a JWT token and return the token data
    pub fn validate_jwt(token: &str) -> Result<jsonwebtoken::TokenData<Claims>, jsonwebtoken::errors::Error> {
        let cfg = Config::init();
        let decoding_key = jsonwebtoken::DecodingKey::from_secret(cfg.jwt_secret.as_bytes());
        let mut validation = jsonwebtoken::Validation::default();
        validation.validate_exp = true;

        jsonwebtoken::decode::<Claims>(token, &decoding_key, &validation)
    }

    /// Validate a JWT token and return only the claims
    #[allow(dead_code)]
    pub fn validate_jwt_claims(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
        let token_data = Self::validate_jwt(token)?;
        Ok(token_data.claims)
    }

    /// Generate a JWT token with custom expiration time (in minutes)
    #[allow(dead_code)]
    pub fn generate_jwt_with_custom_exp(
        user_id: Uuid,
        username: &str,
        minutes: i64
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let cfg = Config::init();
        let now = Utc::now();
        let expire = now + Duration::minutes(minutes);
        let claims = Claims {
            sub: user_id,
            username: username.to_string(),
            exp: expire.timestamp() as usize,
            iat: now.timestamp() as usize,
        };
        encode(&jsonwebtoken::Header::default(), &claims, &jsonwebtoken::EncodingKey::from_secret(cfg.jwt_secret.as_bytes()))
    }

    /// Generate a JWT token with custom claims
    #[allow(dead_code)]
    pub fn generate_jwt_with_custom_claims(
        user_id: Uuid,
        username: &str,
        _custom_claims: Option<std::collections::HashMap<String, String>>
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let cfg = Config::init();
        let now = Utc::now();
        let expire = now + Duration::minutes(cfg.jwt_expires_in);

        // For custom claims, we'll extend the Claims struct with additional fields if needed
        // For now, we'll use the standard Claims and add custom data to username field if needed
        let claims = Claims {
            sub: user_id,
            username: username.to_string(),
            exp: expire.timestamp() as usize,
            iat: now.timestamp() as usize,
        };

        // If you need to add custom claims, you might need to create a separate struct
        // For now, we'll just return the standard token
        encode(&jsonwebtoken::Header::default(), &claims, &jsonwebtoken::EncodingKey::from_secret(cfg.jwt_secret.as_bytes()))
    }

    /// Generate a refresh JWT token with the provided user ID and username
    pub fn generate_refresh_token(user_id: Uuid, username: &str) -> Result<String, jsonwebtoken::errors::Error> {
        let cfg = Config::init();
        // Refresh token expires in 7 days by default
        let refresh_token_expires_in = cfg.jwt_expires_in * 24 * 7; // 7 days in minutes
        let now = Utc::now();
        let expire = now + Duration::minutes(refresh_token_expires_in);
        let claims = RefreshTokenClaims {
            sub: user_id,
            username: username.to_string(),
            exp: expire.timestamp() as usize,
            iat: now.timestamp() as usize,
            token_type: "refresh".to_string(),
        };
        encode(&Header::default(), &claims, &EncodingKey::from_secret(cfg.jwt_secret.as_bytes()))
    }

    /// Validate a refresh JWT token and return the claims
    pub fn validate_refresh_token(token: &str) -> Result<RefreshTokenClaims, jsonwebtoken::errors::Error> {
        let cfg = Config::init();
        let decoding_key = DecodingKey::from_secret(cfg.jwt_secret.as_bytes());
        let mut validation = Validation::default();
        validation.validate_exp = true;

        let token_data = decode::<RefreshTokenClaims>(token, &decoding_key, &validation)?;
        // Additional check to ensure this is indeed a refresh token
        if token_data.claims.token_type != "refresh" {
            return Err(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidToken));
        }
        Ok(token_data.claims)
    }
}