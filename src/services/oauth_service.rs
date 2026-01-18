use axum::http::StatusCode;
use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl,
    TokenResponse, AuthorizationCode, Scope, CsrfToken,
};
use reqwest::Client as ReqwestClient;
use sea_orm::{TransactionTrait, ActiveValue::Set, ActiveModelTrait, EntityTrait, QueryFilter, ColumnTrait, NotSet};
use serde::Deserialize;
use uuid::Uuid;
use chrono::{Utc, Duration};
use crate::config::{Config, AppState};
use crate::entities::{user, user_role, role, session};
use crate::repositories::{oauth_repository::OAuthRepository, user_repository::UserRepository};
use crate::utils::jwt_utils::JwtUtils;
use crate::services::audit_service::AuditService;
use casbin::MgmtApi;

pub struct OAuthService;

#[derive(Debug, Deserialize)]
pub struct OAuthUserProfile {
    pub id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
}

impl OAuthService {
    pub fn get_authorization_url(provider: &str) -> Result<String, (StatusCode, &'static str, String)> {
        let client = Self::create_client(provider)?;
        
        let mut request = client.authorize_url(CsrfToken::new_random);

        match provider {
            "google" => {
                request = request
                    .add_scope(Scope::new("email".to_string()))
                    .add_scope(Scope::new("profile".to_string()));
            },
            "github" => {
                request = request
                    .add_scope(Scope::new("user:email".to_string()))
                    .add_scope(Scope::new("read:user".to_string()));
            },
            _ => {
                // Default fallback
                request = request
                    .add_scope(Scope::new("email".to_string()))
                    .add_scope(Scope::new("profile".to_string()));
            }
        }

        let (auth_url, _csrf_token) = request.url();

        Ok(auth_url.to_string())
    }

    pub async fn verify_and_link(
        state: &AppState,
        provider: &str,
        code: String,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(String, usize, Option<String>, Option<usize>, String), (StatusCode, &'static str, String)> {
        // 1. Exchange Code
        let client = Self::create_client(provider)?;
        let token_result = client
            .exchange_code(AuthorizationCode::new(code))
            .request_async(oauth2::reqwest::async_http_client)
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, "OAUTH_EXCHANGE_ERR", format!("Failed to exchange code: {}", e)))?;

        let access_token = token_result.access_token().secret();

        // 2. Fetch User Profile
        let profile = Self::fetch_profile(provider, access_token).await?;
        
        let email = profile.email.ok_or((StatusCode::BAD_REQUEST, "OAUTH_NO_EMAIL", "Email not provided by OAuth provider".to_string()))?;
        let provider_user_id = profile.id;
        
        let db = &state.db;

        // 3. Start Transaction
        let txn = db.begin().await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "TXN_ERR", "Failed to start transaction".to_string()))?;

        // 4. Check if OAuth Account exists
        let user = if let Some(oauth_account) = OAuthRepository::find_by_provider_and_id(&txn, provider, &provider_user_id)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Database error".to_string()))? 
        {
            // Found: Get User
            user::Entity::find_by_id(oauth_account.user_id)
                .one(&txn)
                .await
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Database error".to_string()))?
                .ok_or((StatusCode::NOT_FOUND, "USER_NOT_FOUND", "User linked to OAuth not found".to_string()))?
        } else {
            // Not Found: Check if User exists by email
            if let Some(existing_user) = UserRepository::find_active_by_login_id(&txn, &email)
                .await
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Database error".to_string()))?
            {
                // Found Email: Link Account
                OAuthRepository::create(
                    &txn,
                    existing_user.id,
                    provider.to_string(),
                    provider_user_id,
                    Some(email.clone()),
                    profile.name.clone(),
                    profile.avatar_url.clone(),
                    Some(access_token.clone()),
                    None, // Refresh token not always available or needed here
                    None
                ).await.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_WRITE_ERR", "Failed to link OAuth account".to_string()))?;
                
                existing_user
            } else {
                // New User: Create User & Link
                let random_password = Uuid::new_v4().to_string(); // Unusable password
                let hashed_password = crate::services::auth_service::AuthService::hash_password(random_password)
                     .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "HASH_ERR", "Failed to hash password".to_string()))?;

                let new_user = UserRepository::create(
                    &txn,
                    profile.name.unwrap_or(email.clone()), // Username fallback to name or email
                    email.clone(),
                    hashed_password
                ).await.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_WRITE_ERR", "Failed to create user".to_string()))?;

                // Auto-verify email for OAuth
                let mut active_user: user::ActiveModel = new_user.clone().into();
                active_user.email_verified = Set(Some(true));
                active_user.email_verified_at = Set(Some(Utc::now()));
                active_user.avatar_url = Set(profile.avatar_url.clone());
                let new_user = active_user.update(&txn).await
                     .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_WRITE_ERR", "Failed to update user verification".to_string()))?;

                // Assign Role
                let role_user = role::Entity::find()
                    .filter(role::Column::Name.eq("user"))
                    .one(&txn)
                    .await
                    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "ROLE_ERR", "Database error".to_string()))?
                    .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "ROLE_NOT_FOUND", "Role 'user' not found".to_string()))?;

                let user_role_link = user_role::ActiveModel {
                    user_id: Set(new_user.id),
                    role_id: Set(role_user.id),
                };
                user_role_link.insert(&txn).await
                    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "ROLE_ASSIGN_ERR", "Failed to assign role".to_string()))?;

                 // Casbin Policy
                 {
                    let mut enforcer = state.enforcer.write().await;
                    let _: bool = enforcer.add_grouping_policy(vec![new_user.public_id.to_string(), "user".to_string()]).await
                        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "CASBIN_ERR", "Failed to add security policy".to_string()))?;
                }

                // Create OAuth Link
                OAuthRepository::create(
                    &txn,
                    new_user.id,
                    provider.to_string(),
                    provider_user_id,
                    Some(email.clone()),
                    None, // Name already in user
                    None, // Avatar already in user
                    Some(access_token.clone()),
                    None,
                    None
                ).await.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_WRITE_ERR", "Failed to link OAuth account".to_string()))?;

                new_user
            }
        };

        txn.commit().await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "TXN_COMMIT_ERR", "Failed to commit transaction".to_string()))?;

        // 5. Generate Session (Copied from AuthService logic)
        let cfg = Config::init();
        let (refresh_token, jti, refresh_exp) = JwtUtils::generate_refresh_token(user.public_id, cfg.jwt_refresh_days)
             .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "JWT_ERR", "Refresh token generation failed".to_string()))?;

        let session = session::ActiveModel {
            id: NotSet,
            public_id: Set(Uuid::now_v7()),
            user_id: Set(user.id),
            refresh_token_jti: Set(jti),
            user_agent: Set(user_agent.clone()),
            ip_address: Set(ip_address.clone()),
            last_activity: Set(Utc::now()),
            expires_at: Set(Utc::now() + Duration::days(cfg.jwt_refresh_days)), 
            created_at: Set(Utc::now()),
            revoked_at: Set(None),
            ..Default::default()
        };

        let saved_session = session.insert(db).await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, "SESSION_ERR", format!("Failed to create session: {}", e)))?;

        let (token, token_exp, _) = JwtUtils::generate_jwt(user.public_id, saved_session.public_id)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "JWT_ERR", "Token generation failed".to_string()))?;

        // Audit Log
        AuditService::log(
            db, Some(user.id), "login_oauth", provider, None, "success",
            None, None, ip_address, user_agent, None, None
        ).await;

        Ok((token, token_exp, Some(refresh_token), Some(refresh_exp), "Bearer".to_string()))
    }

    fn create_client(provider: &str) -> Result<BasicClient, (StatusCode, &'static str, String)> {
        let cfg = Config::init();
        match provider {
            "google" => Ok(
                BasicClient::new(
                    ClientId::new(cfg.google_client_id),
                    Some(ClientSecret::new(cfg.google_client_secret)),
                    AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string()).unwrap(),
                    Some(TokenUrl::new("https://oauth2.googleapis.com/token".to_string()).unwrap())
                )
                .set_redirect_uri(RedirectUrl::new(cfg.google_redirect_url).map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "CONFIG_ERR", "Invalid Google Redirect URL".to_string()))?)
            ),
            "github" => Ok(
                BasicClient::new(
                    ClientId::new(cfg.github_client_id),
                    Some(ClientSecret::new(cfg.github_client_secret)),
                    AuthUrl::new("https://github.com/login/oauth/authorize".to_string()).unwrap(),
                    Some(TokenUrl::new("https://github.com/login/oauth/access_token".to_string()).unwrap())
                )
                .set_redirect_uri(RedirectUrl::new(cfg.github_redirect_url).map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "CONFIG_ERR", "Invalid GitHub Redirect URL".to_string()))?)
            ),
            _ => Err((StatusCode::BAD_REQUEST, "INVALID_PROVIDER", "Provider not supported".to_string()))
        }
    }

    async fn fetch_profile(provider: &str, access_token: &str) -> Result<OAuthUserProfile, (StatusCode, &'static str, String)> {
        let http_client = ReqwestClient::new();
        
        match provider {
            "google" => {
                #[derive(Deserialize)]
                struct GoogleUser {
                    id: String,
                    email: String,
                    name: String,
                    picture: Option<String>,
                }
                
                let resp = http_client
                    .get("https://www.googleapis.com/oauth2/v1/userinfo?alt=json")
                    .bearer_auth(access_token)
                    .send()
                    .await
                    .map_err(|e| (StatusCode::BAD_REQUEST, "GOOGLE_API_ERR", format!("Failed to fetch Google profile: {}", e)))?;
                
                let user: GoogleUser = resp.json().await
                     .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, "JSON_ERR", format!("Failed to parse Google profile: {}", e)))?;

                Ok(OAuthUserProfile {
                    id: user.id,
                    email: Some(user.email),
                    name: Some(user.name),
                    avatar_url: user.picture,
                })
            },
            "github" => {
                #[derive(Deserialize)]
                struct GitHubUser {
                    id: i64,
                    login: String,
                    email: Option<String>,
                    name: Option<String>,
                    avatar_url: Option<String>,
                }

                // 1. Get Profile
                let resp = http_client
                    .get("https://api.github.com/user")
                    .header("User-Agent", "Dakopi-App")
                    .bearer_auth(access_token)
                    .send()
                    .await
                    .map_err(|e| (StatusCode::BAD_REQUEST, "GITHUB_API_ERR", format!("Failed to fetch GitHub profile: {}", e)))?;

                let user: GitHubUser = resp.json().await
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, "JSON_ERR", format!("Failed to parse GitHub profile: {}", e)))?;

                let mut email = user.email;

                // 2. If email is private/null, fetch from emails endpoint
                if email.is_none() {
                    #[derive(Deserialize)]
                    struct GitHubEmail {
                        email: String,
                        primary: bool,
                        verified: bool,
                    }
                    
                    if let Ok(emails_resp) = http_client
                        .get("https://api.github.com/user/emails")
                        .header("User-Agent", "Dakopi-App")
                        .bearer_auth(access_token)
                        .send()
                        .await 
                    {
                        if let Ok(emails) = emails_resp.json::<Vec<GitHubEmail>>().await {
                            email = emails.into_iter()
                                .find(|e| e.primary && e.verified)
                                .map(|e| e.email);
                        }
                    }
                }

                Ok(OAuthUserProfile {
                    id: user.id.to_string(),
                    email,
                    name: user.name.or(Some(user.login)),
                    avatar_url: user.avatar_url,
                })
            },
            _ => Err((StatusCode::BAD_REQUEST, "INVALID_PROVIDER", "Provider not supported".to_string()))
        }
    }
}
