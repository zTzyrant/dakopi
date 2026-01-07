use crate::config::Config;
use crate::models::auth_model::Claims;
use chrono::{Utc, Duration};
use jsonwebtoken::{encode, decode, DecodingKey, Validation, Header, EncodingKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    pub sub: Uuid,
    pub exp: usize,
    pub iat: usize,
    pub jti: String,
    pub token_type: String, 
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFaTempClaims {
    pub sub: Uuid,
    pub exp: usize,
    pub iat: usize,
    pub jti: String, // Added JTI for blacklist
    pub token_type: String, 
}

pub struct JwtUtils;

impl JwtUtils {
    /// Generate Access Token (with JTI for blacklist capability)
    pub fn generate_jwt(user_id: Uuid, session_id: Uuid) -> Result<(String, usize, String), jsonwebtoken::errors::Error> {
        let cfg = Config::init();
        let now = Utc::now();
        let expire = now + Duration::minutes(cfg.jwt_access_minutes);
        let jti = Uuid::now_v7().to_string();
        
        let claims = Claims {
            sub: user_id,
            sid: session_id,
            exp: expire.timestamp() as usize,
            iat: now.timestamp() as usize,
            jti: jti.clone(),
        };
        let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(cfg.jwt_secret.as_bytes()))?;
        Ok((token, expire.timestamp() as usize, jti))
    }

    /// Validate a JWT token and return the token data
    pub fn validate_jwt(token: &str) -> Result<jsonwebtoken::TokenData<Claims>, jsonwebtoken::errors::Error> {
        let cfg = Config::init();
        let decoding_key = jsonwebtoken::DecodingKey::from_secret(cfg.jwt_secret.as_bytes());
        let mut validation = jsonwebtoken::Validation::default();
        validation.validate_exp = true;

        jsonwebtoken::decode::<Claims>(token, &decoding_key, &validation)
    }

    /// Generate 2FA Temp Token (5 mins)
    pub fn generate_2fa_temp_token(user_id: Uuid) -> Result<(String, String), jsonwebtoken::errors::Error> {
        let cfg = Config::init();
        let now = Utc::now();
        let expire = now + Duration::minutes(5); 
        let jti = Uuid::now_v7().to_string();

        let claims = TwoFaTempClaims {
            sub: user_id,
            exp: expire.timestamp() as usize,
            iat: now.timestamp() as usize,
            jti: jti.clone(),
            token_type: "2fa_temp".to_string(),
        };
        let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(cfg.jwt_secret.as_bytes()))?;
        Ok((token, jti))
    }

    /// Validate 2FA Temp Token
    pub fn validate_2fa_temp_token(token: &str) -> Result<TwoFaTempClaims, jsonwebtoken::errors::Error> {
        let cfg = Config::init();
        let decoding_key = DecodingKey::from_secret(cfg.jwt_secret.as_bytes());
        let mut validation = Validation::default();
        validation.validate_exp = true;

        let token_data = decode::<TwoFaTempClaims>(token, &decoding_key, &validation)?;
        if token_data.claims.token_type != "2fa_temp" {
            return Err(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidToken));
        }
        Ok(token_data.claims)
    }

    /// Generate Refresh Token
    /// Returns (token, jti, expires_at_timestamp)
    pub fn generate_refresh_token(user_id: Uuid, days: i64) -> Result<(String, String, usize), jsonwebtoken::errors::Error> {
        let cfg = Config::init();
        let now = Utc::now();
        let expire = now + Duration::days(days);
        let jti = Uuid::now_v7().to_string();

        let claims = RefreshTokenClaims {
            sub: user_id,
            exp: expire.timestamp() as usize,
            iat: now.timestamp() as usize,
            jti: jti.clone(),
            token_type: "refresh".to_string(),
        };
        let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(cfg.jwt_secret.as_bytes()))?;
        Ok((token, jti, expire.timestamp() as usize))
    }

    /// Validate Refresh Token
    pub fn validate_refresh_token(token: &str) -> Result<RefreshTokenClaims, jsonwebtoken::errors::Error> {
        let cfg = Config::init();
        let decoding_key = DecodingKey::from_secret(cfg.jwt_secret.as_bytes());
        let mut validation = Validation::default();
        validation.validate_exp = true;

        let token_data = decode::<RefreshTokenClaims>(token, &decoding_key, &validation)?;
        if token_data.claims.token_type != "refresh" {
            return Err(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidToken));
        }
        Ok(token_data.claims)
    }
}