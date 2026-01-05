# Dakopi Authentication Standard - Best Practices

## 📋 Daftar Isi

1. [Filosofi & Prinsip Dasar](#filosofi--prinsip-dasar)
2. [Arsitektur Authentication](#arsitektur-authentication)
3. [Fitur Core Authentication](#fitur-core-authentication)
4. [Implementasi Detail](#implementasi-detail)
5. [Security Best Practices](#security-best-practices)
6. [Database Schema](#database-schema)
7. [API Endpoints Standard](#api-endpoints-standard)
8. [Error Handling](#error-handling)
9. [Testing Strategy](#testing-strategy)
10. [Migration Path](#migration-path)

---

## Filosofi & Prinsip Dasar

### Design Philosophy

Dakopi authentication system mengadaptasi best practices dari:
- **BetterAuth**: Comprehensive features out-of-the-box
- **OAuth2 RFC 6749**: Industry standard authorization
- **OWASP Guidelines**: Security best practices
- **Rust Ecosystem**: Type safety dan performance

### Core Principles

1. **Security First**: Semua keputusan mengutamakan keamanan
2. **Developer Experience**: API yang mudah digunakan dan predictable
3. **Framework Agnostic**: Tidak terikat pada satu client framework
4. **Extensible**: Plugin-based architecture untuk fitur tambahan
5. **Type Safe**: Leverage Rust's type system untuk compile-time safety

---

## Arsitektur Authentication

### Layered Architecture

```
┌─────────────────────────────────────────┐
│         Handlers (Controllers)          │
│  - Request parsing & validation         │
│  - Response formatting                  │
└─────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────┐
│              Services                    │
│  - Business logic                       │
│  - Token management                     │
│  - Session handling                     │
└─────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────┐
│            Repositories                  │
│  - Database queries                     │
│  - Data persistence                     │
└─────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────┐
│               Database                   │
│  - PostgreSQL (recommended)             │
│  - MySQL / SQLite (supported)           │
└─────────────────────────────────────────┘
```

### Authentication Flow Types

#### 1. Credential-Based Authentication (Email/Password)
```
Client → Register/Login → Service validates → Generate tokens → Return session
```

#### 2. OAuth2 Social Login
```
Client → OAuth Provider → Callback → Service validates → Link/Create account → Return session
```

#### 3. Passwordless (Magic Link / OTP)
```
Client → Request token → Service generates → Send via email/SMS → Verify token → Return session
```

#### 4. Two-Factor Authentication (2FA)
```
Normal login → Generate TOTP → Verify 2FA code → Return session
```

---

## Fitur Core Authentication

### ✅ Level 1: Essential Features (Must Have)

1. **Email & Password Authentication**
   - Secure password hashing (Argon2)
   - Email verification
   - Password reset flow
   - Rate limiting

2. **JWT-based Sessions**
   - Access token (short-lived: 15 min - 1 hour)
   - Refresh token (long-lived: 7-30 days)
   - Token rotation on refresh
   - Blacklist untuk revoked tokens

3. **Account Management**
   - User registration
   - Email verification
   - Profile update
   - Account deletion (soft delete)

4. **Security Basics**
   - CSRF protection
   - Rate limiting (login attempts, registration)
   - Password policies (min length, complexity)
   - Secure session cookies (HttpOnly, Secure, SameSite)

### ⭐ Level 2: Enhanced Features (Should Have)

1. **OAuth2 Social Login**
   - Google, GitHub, Facebook, Twitter
   - Account linking (multiple providers per user)
   - Provider-specific data mapping

2. **Multi-Factor Authentication (MFA)**
   - TOTP (Time-based OTP) - Google Authenticator
   - SMS OTP
   - Backup codes
   - Recovery email

3. **Session Management**
   - Multiple concurrent sessions
   - Device tracking (last seen, device info)
   - Remote logout (revoke specific sessions)
   - Session timeout & renewal

4. **Passwordless Authentication**
   - Magic link via email
   - OTP via SMS
   - WebAuthn/Passkeys (future)

### 🚀 Level 3: Advanced Features (Nice to Have)

1. **Organization & Multi-Tenancy**
   - Organizations/Teams
   - Role-based access control (RBAC)
   - Invitation system
   - Member management

2. **Enterprise Features**
   - SSO (SAML 2.0)
   - LDAP/Active Directory
   - Audit logs
   - Compliance reporting

3. **Security Enhancements**
   - Geolocation-based anomaly detection
   - Device fingerprinting
   - Suspicious activity alerts
   - Brute force protection with progressive delays

---

## Implementasi Detail

### 1. Password Security

```rust
// src/services/auth_service.rs
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Algorithm, Version, Params
};
use rand_core::OsRng;

pub struct PasswordService;

impl PasswordService {
    /// Hash password with Argon2id (recommended by OWASP)
    pub fn hash_password(password: &str) -> Result<String, AuthError> {
        // Argon2id configuration (balanced between Argon2i and Argon2d)
        let params = Params::new(
            15_000,  // Memory cost (15 MB)
            2,       // Time cost (iterations)
            1,       // Parallelism
            None     // Output length
        )?;
        
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            params
        );
        
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)?
            .to_string();
        
        Ok(password_hash)
    }
    
    /// Verify password against hash
    pub fn verify_password(password: &str, hash: &str) -> Result<bool, AuthError> {
        let parsed_hash = PasswordHash::new(hash)?;
        let argon2 = Argon2::default();
        
        Ok(argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok())
    }
    
    /// Check password strength (OWASP recommendations)
    pub fn validate_password_strength(password: &str) -> Result<(), ValidationError> {
        if password.len() < 8 {
            return Err(ValidationError::new("password_too_short"));
        }
        
        if password.len() > 128 {
            return Err(ValidationError::new("password_too_long"));
        }
        
        // Check for common patterns
        let has_uppercase = password.chars().any(|c| c.is_uppercase());
        let has_lowercase = password.chars().any(|c| c.is_lowercase());
        let has_digit = password.chars().any(|c| c.is_numeric());
        let has_special = password.chars().any(|c| !c.is_alphanumeric());
        
        let strength_score = [has_uppercase, has_lowercase, has_digit, has_special]
            .iter()
            .filter(|&&x| x)
            .count();
        
        if strength_score < 3 {
            return Err(ValidationError::new("password_too_weak"));
        }
        
        Ok(())
    }
}
```

### 2. JWT Token Management

```rust
// src/services/token_service.rs
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use chrono::{Utc, Duration};

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,           // Subject (user_id)
    pub email: String,
    pub roles: Vec<String>,
    pub iat: i64,              // Issued at
    pub exp: i64,              // Expiration
    pub jti: String,           // JWT ID (for blacklisting)
    #[serde(rename = "type")]
    pub token_type: TokenType, // access or refresh
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenType {
    Access,
    Refresh,
}

pub struct TokenService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    access_token_ttl: Duration,
    refresh_token_ttl: Duration,
}

impl TokenService {
    pub fn new(secret: &str) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
            access_token_ttl: Duration::minutes(15),   // Short-lived
            refresh_token_ttl: Duration::days(30),     // Long-lived
        }
    }
    
    /// Generate access token
    pub fn generate_access_token(
        &self,
        user_id: Uuid,
        email: String,
        roles: Vec<String>,
    ) -> Result<String, TokenError> {
        let now = Utc::now();
        let claims = TokenClaims {
            sub: user_id.to_string(),
            email,
            roles,
            iat: now.timestamp(),
            exp: (now + self.access_token_ttl).timestamp(),
            jti: Uuid::now_v7().to_string(),
            token_type: TokenType::Access,
        };
        
        let token = encode(&Header::new(Algorithm::HS256), &claims, &self.encoding_key)?;
        Ok(token)
    }
    
    /// Generate refresh token
    pub fn generate_refresh_token(
        &self,
        user_id: Uuid,
        email: String,
    ) -> Result<String, TokenError> {
        let now = Utc::now();
        let claims = TokenClaims {
            sub: user_id.to_string(),
            email,
            roles: vec![],  // Refresh tokens don't carry roles
            iat: now.timestamp(),
            exp: (now + self.refresh_token_ttl).timestamp(),
            jti: Uuid::now_v7().to_string(),
            token_type: TokenType::Refresh,
        };
        
        let token = encode(&Header::new(Algorithm::HS256), &claims, &self.encoding_key)?;
        Ok(token)
    }
    
    /// Verify and decode token
    pub fn verify_token(&self, token: &str) -> Result<TokenClaims, TokenError> {
        let validation = Validation::new(Algorithm::HS256);
        let token_data = decode::<TokenClaims>(token, &self.decoding_key, &validation)?;
        
        // Check if token is blacklisted
        // TODO: Implement blacklist check in Redis/Database
        
        Ok(token_data.claims)
    }
    
    /// Generate token pair (access + refresh)
    pub fn generate_token_pair(
        &self,
        user_id: Uuid,
        email: String,
        roles: Vec<String>,
    ) -> Result<TokenPair, TokenError> {
        Ok(TokenPair {
            access_token: self.generate_access_token(user_id, email.clone(), roles)?,
            refresh_token: self.generate_refresh_token(user_id, email)?,
            token_type: "Bearer".to_string(),
            expires_in: self.access_token_ttl.num_seconds(),
        })
    }
}

#[derive(Debug, Serialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}
```

### 3. Session Management

```rust
// src/entities/session.rs
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "sessions")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    
    pub user_id: Uuid,
    pub refresh_token_jti: String,  // JWT ID for tracking
    
    // Device/Client info
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub device_type: Option<String>,  // mobile, desktop, tablet
    pub device_name: Option<String>,
    
    // Timestamps
    pub last_activity: DateTimeUtc,
    pub expires_at: DateTimeUtc,
    pub created_at: DateTimeUtc,
    pub revoked_at: Option<DateTimeUtc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::user::Entity",
        from = "Column::UserId",
        to = "super::user::Column::Id"
    )]
    User,
}

impl Related<super::user::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::User.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

// src/services/session_service.rs
pub struct SessionService;

impl SessionService {
    /// Create new session
    pub async fn create_session(
        db: &DatabaseConnection,
        user_id: Uuid,
        refresh_token_jti: String,
        user_agent: Option<String>,
        ip_address: Option<String>,
    ) -> Result<session::Model, DbErr> {
        let now = Utc::now();
        let session = session::ActiveModel {
            id: Set(Uuid::now_v7()),
            user_id: Set(user_id),
            refresh_token_jti: Set(refresh_token_jti),
            user_agent: Set(user_agent),
            ip_address: Set(ip_address),
            device_type: Set(Self::detect_device_type(&user_agent)),
            last_activity: Set(now),
            expires_at: Set(now + Duration::days(30)),
            created_at: Set(now),
            revoked_at: Set(None),
            ..Default::default()
        };
        
        session.insert(db).await
    }
    
    /// Get active sessions for user
    pub async fn get_user_sessions(
        db: &DatabaseConnection,
        user_id: Uuid,
    ) -> Result<Vec<session::Model>, DbErr> {
        session::Entity::find()
            .filter(session::Column::UserId.eq(user_id))
            .filter(session::Column::RevokedAt.is_null())
            .filter(session::Column::ExpiresAt.gt(Utc::now()))
            .all(db)
            .await
    }
    
    /// Revoke session
    pub async fn revoke_session(
        db: &DatabaseConnection,
        session_id: Uuid,
    ) -> Result<(), DbErr> {
        let session = session::Entity::find_by_id(session_id)
            .one(db)
            .await?
            .ok_or(DbErr::RecordNotFound("Session not found".into()))?;
        
        let mut session: session::ActiveModel = session.into();
        session.revoked_at = Set(Some(Utc::now()));
        session.update(db).await?;
        
        Ok(())
    }
    
    /// Revoke all sessions for user (except current)
    pub async fn revoke_all_sessions_except(
        db: &DatabaseConnection,
        user_id: Uuid,
        current_session_id: Uuid,
    ) -> Result<(), DbErr> {
        session::Entity::update_many()
            .col_expr(
                session::Column::RevokedAt,
                Expr::value(Utc::now())
            )
            .filter(session::Column::UserId.eq(user_id))
            .filter(session::Column::Id.ne(current_session_id))
            .filter(session::Column::RevokedAt.is_null())
            .exec(db)
            .await?;
        
        Ok(())
    }
    
    /// Update session activity
    pub async fn update_activity(
        db: &DatabaseConnection,
        session_id: Uuid,
    ) -> Result<(), DbErr> {
        session::Entity::update_many()
            .col_expr(
                session::Column::LastActivity,
                Expr::value(Utc::now())
            )
            .filter(session::Column::Id.eq(session_id))
            .exec(db)
            .await?;
        
        Ok(())
    }
    
    /// Cleanup expired sessions (run as cron job)
    pub async fn cleanup_expired_sessions(
        db: &DatabaseConnection,
    ) -> Result<u64, DbErr> {
        let result = session::Entity::delete_many()
            .filter(session::Column::ExpiresAt.lt(Utc::now()))
            .exec(db)
            .await?;
        
        Ok(result.rows_affected)
    }
    
    fn detect_device_type(user_agent: &Option<String>) -> Option<String> {
        // Simple device detection logic
        user_agent.as_ref().map(|ua| {
            let ua_lower = ua.to_lowercase();
            if ua_lower.contains("mobile") || ua_lower.contains("android") {
                "mobile".to_string()
            } else if ua_lower.contains("tablet") || ua_lower.contains("ipad") {
                "tablet".to_string()
            } else {
                "desktop".to_string()
            }
        })
    }
}
```

### 4. Rate Limiting

```rust
// src/middleware/rate_limiter.rs
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use std::time::{Duration, Instant};

pub struct RateLimiter {
    requests: Arc<RwLock<HashMap<String, Vec<Instant>>>>,
    max_requests: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            requests: Arc::new(RwLock::new(HashMap::new())),
            max_requests,
            window,
        }
    }
    
    /// Check if request is allowed
    pub async fn check_rate_limit(&self, identifier: &str) -> bool {
        let mut requests = self.requests.write().await;
        let now = Instant::now();
        
        // Clean old entries
        let cutoff = now - self.window;
        
        let entry = requests.entry(identifier.to_string()).or_insert_with(Vec::new);
        entry.retain(|&timestamp| timestamp > cutoff);
        
        if entry.len() >= self.max_requests {
            return false;
        }
        
        entry.push(now);
        true
    }
    
    /// Get remaining requests
    pub async fn get_remaining(&self, identifier: &str) -> usize {
        let requests = self.requests.read().await;
        if let Some(entry) = requests.get(identifier) {
            let now = Instant::now();
            let cutoff = now - self.window;
            let valid_requests = entry.iter().filter(|&&ts| ts > cutoff).count();
            self.max_requests.saturating_sub(valid_requests)
        } else {
            self.max_requests
        }
    }
}

// Axum middleware implementation
use axum::{
    middleware::Next,
    response::{IntoResponse, Response},
    extract::{Request, State},
    http::StatusCode,
};

pub async fn rate_limit_middleware(
    State(limiter): State<Arc<RateLimiter>>,
    request: Request,
    next: Next,
) -> Response {
    // Get identifier (IP address or user ID)
    let identifier = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown")
        .to_string();
    
    if !limiter.check_rate_limit(&identifier).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ApiResponse::<()>::error(
                "RATE_LIMIT_EXCEEDED",
                "Too many requests. Please try again later.",
            ))
        ).into_response();
    }
    
    next.run(request).await
}
```

---

## Security Best Practices

### 1. OWASP Top 10 Compliance

#### A01: Broken Access Control
- ✅ Implement proper RBAC
- ✅ Validate user permissions on every request
- ✅ Use middleware untuk auth checks
- ✅ Never trust client-side role claims

#### A02: Cryptographic Failures
- ✅ Use Argon2id untuk password hashing
- ✅ TLS 1.3 untuk semua connections
- ✅ Secure random token generation
- ✅ Proper key rotation strategy

#### A03: Injection
- ✅ Use SeaORM parameterized queries
- ✅ Input validation di DTO layer
- ✅ Sanitize user inputs

#### A07: Authentication Failures
- ✅ Multi-factor authentication
- ✅ Rate limiting untuk login attempts
- ✅ Secure password policies
- ✅ Account lockout mechanisms

### 2. Token Security

```rust
// Token Storage Recommendations
// ❌ DON'T: Store in localStorage (vulnerable to XSS)
// ❌ DON'T: Store in session storage
// ✅ DO: Use HttpOnly, Secure cookies for refresh tokens
// ✅ DO: Store access tokens in memory only
// ✅ DO: Implement CSRF protection with cookies

// Cookie configuration
pub fn create_refresh_token_cookie(token: &str) -> Cookie<'static> {
    Cookie::build(("refresh_token", token.to_owned()))
        .path("/")
        .http_only(true)
        .secure(true)  // HTTPS only
        .same_site(SameSite::Strict)
        .max_age(Duration::days(30))
        .finish()
}
```

### 3. CSRF Protection

```rust
// src/middleware/csrf.rs
use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
    http::{StatusCode, HeaderMap},
};

pub async fn csrf_middleware(
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Skip CSRF for GET, HEAD, OPTIONS
    let method = request.method();
    if method == "GET" || method == "HEAD" || method == "OPTIONS" {
        return Ok(next.run(request).await);
    }
    
    // Verify CSRF token
    let csrf_token = headers
        .get("x-csrf-token")
        .and_then(|h| h.to_str().ok());
    
    let cookie_token = request
        .headers()
        .get("cookie")
        .and_then(|h| h.to_str().ok())
        .and_then(|c| extract_csrf_from_cookie(c));
    
    if csrf_token.is_none() || cookie_token.is_none() || csrf_token != cookie_token {
        return Err(StatusCode::FORBIDDEN);
    }
    
    Ok(next.run(request).await)
}
```

### 4. Audit Logging

```rust
// src/entities/audit_log.rs
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "audit_logs")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    
    pub user_id: Option<Uuid>,
    pub action: String,              // login, logout, password_change, etc.
    pub resource: String,             // users, sessions, etc.
    pub resource_id: Option<String>,
    
    // Request context
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub method: String,               // HTTP method
    pub path: String,                 // Request path
    
    // Result
    pub status: String,               // success, failure
    pub error_message: Option<String>,
    
    // Metadata
    pub metadata: Option<Json>,       // Additional contextual data
    
    pub created_at: DateTimeUtc,
}

// Usage
pub async fn log_authentication_event(
    db: &DatabaseConnection,
    user_id: Option<Uuid>,
    action: &str,
    status: &str,
    ip_address: Option<String>,
) -> Result<(), DbErr> {
    let log = audit_log::ActiveModel {
        id: Set(Uuid::now_v7()),
        user_id: Set(user_id),
        action: Set(action.to_string()),
        resource: Set("authentication".to_string()),
        ip_address: Set(ip_address),
        status: Set(status.to_string()),
        created_at: Set(Utc::now()),
        ..Default::default()
    };
    
    log.insert(db).await?;
    Ok(())
}
```

---

## Database Schema

```sql
-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    email_verified_at TIMESTAMP,
    
    password_hash VARCHAR(255),  -- Nullable for OAuth-only accounts
    
    -- Profile
    name VARCHAR(255),
    avatar_url TEXT,
    
    -- Security
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    two_factor_secret VARCHAR(255),
    backup_codes TEXT[],
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    last_login_at TIMESTAMP,
    
    -- Timestamps
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMP
);

CREATE INDEX idx_users_email ON users(email) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_deleted_at ON users(deleted_at);

-- OAuth accounts
CREATE TABLE oauth_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    provider VARCHAR(50) NOT NULL,  -- google, github, facebook, etc.
    provider_user_id VARCHAR(255) NOT NULL,
    
    -- Provider data
    access_token TEXT,
    refresh_token TEXT,
    token_expires_at TIMESTAMP,
    
    -- Profile from provider
    provider_email VARCHAR(255),
    provider_name VARCHAR(255),
    provider_avatar TEXT,
    
    raw_profile JSONB,  -- Store complete provider response
    
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    UNIQUE(provider, provider_user_id)
);

CREATE INDEX idx_oauth_accounts_user_id ON oauth_accounts(user_id);
CREATE INDEX idx_oauth_accounts_provider ON oauth_accounts(provider, provider_user_id);

-- Sessions table
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_jti VARCHAR(255) UNIQUE NOT NULL,
    
    -- Device info
    user_agent TEXT,
    ip_address INET,
    device_type VARCHAR(50),
    device_name VARCHAR(255),
    
    -- Location (optional, for security monitoring)
    country VARCHAR(2),
    city VARCHAR(100),
    
    -- Timestamps
    last_activity TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMP
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_jti ON sessions(refresh_token_jti);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);

-- Token blacklist (for logout before expiry)
CREATE TABLE token_blacklist (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    jti VARCHAR(255) UNIQUE NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_token_blacklist_jti ON token_blacklist(jti);
CREATE INDEX idx_token_blacklist_expires_at ON token_blacklist(expires_at);

-- Email verification tokens
CREATE TABLE email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_email_verification_tokens_token ON email_verification_tokens(token);
CREATE INDEX idx_email_verification_tokens_user_id ON email_verification_tokens(user_id);

-- Password reset tokens
CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_password_reset_tokens_token ON password_reset_tokens(token);
CREATE INDEX idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);

-- Audit logs
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    
    action VARCHAR(100) NOT NULL,  -- login, logout, password_change, etc.
    resource VARCHAR(100) NOT NULL,
    resource_id VARCHAR(255),
    
    -- Request context
    ip_address INET,
    user_agent TEXT,
    method VARCHAR(10),
    path TEXT,
    
    -- Result
    status VARCHAR(20) NOT NULL,  -- success, failure
    error_message TEXT,
    
    -- Additional data
    metadata JSONB,
    
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at DESC);

-- Roles (for RBAC)
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    permissions JSONB,  -- Array of permission strings
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_roles_name ON roles(name);

-- User roles mapping
CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_role_id ON user_roles(role_id);

-- Organizations (for multi-tenancy)
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    logo_url TEXT,
    settings JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMP
);

CREATE INDEX idx_organizations_slug ON organizations(slug) WHERE deleted_at IS NULL;

-- Organization members
CREATE TABLE organization_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(50) NOT NULL,  -- owner, admin, member
    joined_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(organization_id, user_id)
);

CREATE INDEX idx_organization_members_org_id ON organization_members(organization_id);
CREATE INDEX idx_organization_members_user_id ON organization_members(user_id);
```

---

## API Endpoints Standard

### Authentication Endpoints

```
POST   /api/v1/auth/register                 - Register new user
POST   /api/v1/auth/login                    - Login with credentials
POST   /api/v1/auth/logout                   - Logout (revoke current session)
POST   /api/v1/auth/refresh                  - Refresh access token
GET    /api/v1/auth/me                       - Get current user

POST   /api/v1/auth/verify-email             - Send verification email
GET    /api/v1/auth/verify-email/:token      - Verify email with token

POST   /api/v1/auth/password/forgot          - Request password reset
POST   /api/v1/auth/password/reset           - Reset password with token
POST   /api/v1/auth/password/change          - Change password (authenticated)

GET    /api/v1/auth/sessions                 - List all sessions
DELETE /api/v1/auth/sessions/:id             - Revoke specific session
DELETE /api/v1/auth/sessions                 - Revoke all sessions (except current)
```

### OAuth Endpoints

```
GET    /api/v1/auth/oauth/:provider          - Initiate OAuth flow
GET    /api/v1/auth/oauth/:provider/callback - OAuth callback handler
POST   /api/v1/auth/oauth/:provider/link     - Link OAuth account
DELETE /api/v1/auth/oauth/:provider          - Unlink OAuth account
```

### MFA Endpoints

```
POST   /api/v1/auth/2fa/setup                - Setup 2FA (get QR code)
POST   /api/v1/auth/2fa/verify               - Verify 2FA setup
POST   /api/v1/auth/2fa/disable              - Disable 2FA
POST   /api/v1/auth/2fa/verify-login         - Verify 2FA during login
GET    /api/v1/auth/2fa/backup-codes         - Get backup codes
POST   /api/v1/auth/2fa/backup-codes/regenerate - Regenerate backup codes
```

### Example Request/Response

#### Register
```http
POST /api/v1/auth/register
Content-Type: application/json

{
  "email": "[email protected]",
  "password": "SecurePass123!",
  "name": "John Doe"
}
```

```json
{
  "status": "success",
  "code": "AUTH_REGISTER_SUCCESS",
  "message": "Registration successful. Please verify your email.",
  "data": {
    "user": {
      "id": "01936f2a-8b32-7890-a456-123456789012",
      "email": "[email protected]",
      "name": "John Doe",
      "email_verified": false,
      "created_at": "2025-01-05T10:30:00Z"
    }
  }
}
```

#### Login
```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "[email protected]",
  "password": "SecurePass123!"
}
```

```json
{
  "status": "success",
  "code": "AUTH_LOGIN_SUCCESS",
  "message": "Login successful",
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "Bearer",
    "expires_in": 900,
    "user": {
      "id": "01936f2a-8b32-7890-a456-123456789012",
      "email": "[email protected]",
      "name": "John Doe",
      "email_verified": true
    }
  }
}
```

---

## Error Handling

### Standard Error Codes

```rust
pub enum AuthErrorCode {
    // Registration errors
    EMAIL_ALREADY_EXISTS,
    INVALID_EMAIL_FORMAT,
    PASSWORD_TOO_WEAK,
    
    // Login errors
    INVALID_CREDENTIALS,
    EMAIL_NOT_VERIFIED,
    ACCOUNT_LOCKED,
    ACCOUNT_DISABLED,
    TWO_FACTOR_REQUIRED,
    
    // Token errors
    TOKEN_EXPIRED,
    TOKEN_INVALID,
    TOKEN_REVOKED,
    REFRESH_TOKEN_INVALID,
    
    // Session errors
    SESSION_NOT_FOUND,
    SESSION_EXPIRED,
    SESSION_REVOKED,
    
    // Rate limiting
    RATE_LIMIT_EXCEEDED,
    TOO_MANY_ATTEMPTS,
    
    // OAuth errors
    OAUTH_PROVIDER_ERROR,
    OAUTH_ACCOUNT_NOT_LINKED,
    OAUTH_ACCOUNT_ALREADY_LINKED,
    
    // MFA errors
    INVALID_MFA_CODE,
    MFA_NOT_ENABLED,
    MFA_ALREADY_ENABLED,
    
    // General errors
    VALIDATION_ERROR,
    INTERNAL_SERVER_ERROR,
    UNAUTHORIZED,
    FORBIDDEN,
}
```

### Error Response Format

```json
{
  "status": "error",
  "code": "INVALID_CREDENTIALS",
  "message": "Invalid email or password",
  "data": null
}
```

### Validation Error Format

```json
{
  "status": "error",
  "code": "VALIDATION_ERROR",
  "message": "Validation failed",
  "data": [
    {
      "field": "email",
      "title": "invalid_email",
      "message": "Invalid email format"
    },
    {
      "field": "password",
      "title": "password_too_weak",
      "message": "Password must be at least 8 characters and contain uppercase, lowercase, number, and special character"
    }
  ]
}
```

---

## Testing Strategy

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_password_hashing() {
        let password = "SecurePass123!";
        let hash = PasswordService::hash_password(password).unwrap();
        
        assert!(PasswordService::verify_password(password, &hash).unwrap());
        assert!(!PasswordService::verify_password("WrongPass", &hash).unwrap());
    }
    
    #[test]
    fn test_password_strength_validation() {
        assert!(PasswordService::validate_password_strength("Ab1!5678").is_ok());
        assert!(PasswordService::validate_password_strength("short").is_err());
        assert!(PasswordService::validate_password_strength("NoDigitsOrSpecial").is_err());
    }
    
    #[tokio::test]
    async fn test_token_generation_and_verification() {
        let token_service = TokenService::new("test_secret_key_minimum_32_chars");
        let user_id = Uuid::now_v7();
        
        let token = token_service
            .generate_access_token(user_id, "[email protected]".into(), vec!["user".into()])
            .unwrap();
        
        let claims = token_service.verify_token(&token).unwrap();
        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.email, "[email protected]");
    }
}
```

### Integration Tests

```rust
#[cfg(test)]
mod integration_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_complete_registration_flow() {
        let app = create_test_app().await;
        
        // Register
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/auth/register")
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({
                        "email": "[email protected]",
                        "password": "SecurePass123!",
                        "name": "Test User"
                    }).to_string()))
                    .unwrap()
            )
            .await
            .unwrap();
        
        assert_eq!(response.status(), StatusCode::CREATED);
        
        // Verify email can be sent
        // Login should fail until verified
        // etc.
    }
}
```

---

## Migration Path

### Phase 1: Core Authentication (Week 1-2)
- [ ] Setup database schema
- [ ] Implement password hashing
- [ ] Basic registration & login
- [ ] JWT token generation & verification
- [ ] Basic session management
- [ ] Email verification

### Phase 2: Enhanced Security (Week 3-4)
- [ ] Rate limiting
- [ ] CSRF protection
- [ ] Refresh token rotation
- [ ] Session management (multiple devices)
- [ ] Audit logging
- [ ] Password reset flow

### Phase 3: OAuth & Social Login (Week 5-6)
- [ ] OAuth2 framework setup
- [ ] Google OAuth
- [ ] GitHub OAuth
- [ ] Facebook OAuth
- [ ] Account linking

### Phase 4: Advanced Features (Week 7-8)
- [ ] Two-Factor Authentication (TOTP)
- [ ] Backup codes
- [ ] SMS OTP (optional)
- [ ] Organization/Multi-tenancy
- [ ] RBAC implementation

### Phase 5: Enterprise Features (Future)
- [ ] SSO (SAML 2.0)
- [ ] LDAP/Active Directory
- [ ] Advanced audit logging
- [ ] Anomaly detection
- [ ] WebAuthn/Passkeys

---

## Dependencies

```toml
[dependencies]
# Web Framework
axum = "0.8"
tower = "0.5"
tower-http = { version = "0.6", features = ["fs", "cors", "trace"] }

# Database
sea-orm = { version = "1.1", features = ["sqlx-postgres", "runtime-tokio-rustls", "macros"] }
sea-orm-migration = "1.1"

# Authentication
jsonwebtoken = "9"
argon2 = "0.5"
rand_core = { version = "0.6", features = ["std"] }

# OAuth2
oauth2 = "4"
reqwest = { version = "0.12", features = ["json"] }

# Validation
validator = { version = "0.18", features = ["derive"] }
email_address = "0.2"

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Time
chrono = { version = "0.4", features = ["serde"] }

# UUID
uuid = { version = "1", features = ["serde", "v7"] }

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# Config
dotenvy = "0.15"

# Async Runtime
tokio = { version = "1", features = ["full"] }

# 2FA
totp-rs = "5"
qrcode = "0.14"

# Rate Limiting (optional: use Redis)
redis = { version = "0.26", features = ["tokio-comp"], optional = true }
```

---

## Referensi & Resources

### Documentation
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OAuth 2.0 RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
- [JWT Best Practices RFC 8725](https://datatracker.ietf.org/doc/html/rfc8725)
- [Argon2 RFC 9106](https://datatracker.ietf.org/doc/html/rfc9106)

### Rust Crates
- [jsonwebtoken](https://docs.rs/jsonwebtoken/)
- [argon2](https://docs.rs/argon2/)
- [oauth2](https://docs.rs/oauth2/)
- [sea-orm](https://www.sea-ql.org/SeaORM/)
- [axum](https://docs.rs/axum/)

### Inspiration
- [BetterAuth](https://www.better-auth.com/) - Comprehensive TypeScript auth framework
- [Auth.js](https://authjs.dev/) - Popular Next.js authentication
- [Clerk](https://clerk.com/) - Modern authentication platform
- [Auth0](https://auth0.com/) - Enterprise identity platform

---

## Kesimpulan

Dokumentasi ini menyediakan blueprint lengkap untuk implementasi authentication system yang modern, aman, dan scalable untuk Dakopi backend. 

**Key Takeaways:**
1. **Security First**: Gunakan Argon2, JWT best practices, OWASP guidelines
2. **Modular Design**: Plugin-based architecture untuk extensibility
3. **Developer Experience**: Clear API, good error messages, type safety
4. **Production Ready**: Audit logging, rate limiting, monitoring
5. **Future Proof**: Support untuk OAuth, MFA, Multi-tenancy

**Next Steps:**
1. Review dan diskusikan dengan tim
2. Prioritas fitur berdasarkan kebutuhan bisnis
3. Setup development environment
4. Mulai implementasi phase-by-phase
5. Testing komprehensif di setiap phase

---

**Version:** 1.0.0  
**Last Updated:** 2025-01-05  
**Author:** Dakopi Team