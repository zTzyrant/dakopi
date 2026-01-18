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
// ... Argon2 implementation ...
```

### 2. JWT Token Management

```rust
// src/services/token_service.rs
// ... JWT implementation ...
```

### 3. Session Management

```rust
// src/entities/session.rs
// ... Session implementation ...
```

### 4. OAuth2 Strategy (Trust Email & Auto-Link)

Sistem menggunakan strategi **"Trust Email"** untuk menghubungkan akun sosial:

1.  **Trust Email**: Kita mempercayai email yang dikembalikan oleh provider besar (Google, GitHub) karena mereka telah memverifikasinya.
2.  **Auto-Link Flow**:
    *   Jika email dari OAuth **sudah ada** di tabel `users` (misal user pernah daftar manual), sistem otomatis menautkan akun OAuth tersebut ke user yang ada.
    *   User tidak perlu login manual untuk menautkan akun (Frictionless experience).
3.  **Auto-Register**:
    *   Jika email belum ada, sistem otomatis membuat user baru dengan password acak.
    *   User langsung diberi role `user` dan status `email_verified = true`.

### 5. Rate Limiting

```rust
// src/middleware/rate_limiter.rs
// ... Rate limiting implementation ...
```

---

## Security Best Practices

### 1. OWASP Top 10 Compliance

#### A01: Broken Access Control

- ✅ Implement proper RBAC (Casbin)
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
// ... CSRF Implementation ...
```

### 4. Audit Logging

```rust
// src/entities/audit_log.rs
// ... Audit Log Implementation ...
```

---

## Database Schema

(Refer to migration files for full schema: Users, OAuthAccounts, Sessions, Roles, AuditLogs)

---

## API Endpoints Standard

### Authentication Endpoints

```
POST   /api/v1/auth/register                 - Register new user
POST   /api/v1/auth/login                    - Login with credentials (supports remember_me)
POST   /api/v1/auth/logout                   - Logout (revoke current session & blacklist access token)
POST   /api/v1/auth/refresh                  - Refresh access token
GET    /api/v1/auth/me                       - Get current user (Profile)

POST   /api/v1/auth/verify-email             - Send verification email
GET    /api/v1/auth/verify-email/{token}     - Verify email with token

POST   /api/v1/auth/password/forgot          - Request password reset
POST   /api/v1/auth/password/reset           - Reset password with token
POST   /api/v1/auth/password/change          - Change password (authenticated)

GET    /api/v1/auth/sessions                 - List all sessions
DELETE /api/v1/auth/sessions/{id}            - Revoke specific session
DELETE /api/v1/auth/sessions                 - Revoke all sessions (except current)
```

### OAuth Endpoints

```
GET    /api/v1/auth/oauth/{provider}          - Get Redirect URL (google, github)
GET    /api/v1/auth/oauth/{provider}/callback - Handle OAuth Callback & Login
```

### MFA Endpoints

```
POST   /api/v1/auth/2fa/setup                - Setup 2FA (returns secret & QR base64)
POST   /api/v1/auth/2fa/confirm              - Confirm & Enable 2FA
POST   /api/v1/auth/2fa/disable              - Disable 2FA (requires password)
POST   /api/v1/auth/2fa/verify-login         - Verify 2FA during login (exchange temp token)
GET    /api/v1/auth/2fa/backup-codes         - Get backup codes (Planned)
POST   /api/v1/auth/2fa/backup-codes/regenerate - Regenerate backup codes (Planned)
```

---

## Migration Path

### Phase 1: Core Authentication (Completed ✅)

- [x] Setup database schema
- [x] Implement password hashing
- [x] Basic registration & login
- [x] JWT token generation & verification
- [x] Basic session management
- [x] Email verification

### Phase 2: Enhanced Security (Completed ✅)

- [x] Rate limiting
- [x] CSRF protection (via Header/Cookie check)
- [x] Refresh token rotation
- [x] Session management (Get All, Revoke, Revoke All)
- [x] Token Blacklist (Redis-based Access Token revocation)
- [x] User Data Caching (Redis)
- [x] Audit logging (Schema ready, Logic pending)
- [x] Password reset flow

### Phase 3: OAuth & Social Login (Completed ✅)

- [x] OAuth2 framework setup
- [x] Google OAuth
- [x] GitHub OAuth
- [ ] Facebook OAuth (Skipped by request)
- [x] Account linking (Trust Email strategy)

### Phase 4: Advanced Features (Partially Completed)

- [x] Two-Factor Authentication (TOTP)
- [x] Backup codes
- [ ] SMS OTP (optional)
- [x] RBAC implementation (Casbin)
- [ ] Organization/Multi-tenancy

### Phase 5: Enterprise Features (Future)

- [ ] SSO (SAML 2.0)
- [ ] LDAP/Active Directory
- [ ] Advanced audit logging
- [ ] Anomaly detection
- [ ] WebAuthn/Passkeys

---

**Version:** 1.1.0
**Last Updated:** 2026-01-11
**Author:** Dakopi Team