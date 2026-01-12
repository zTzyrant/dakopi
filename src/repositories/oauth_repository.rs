use sea_orm::*;
use chrono::Utc;
use uuid::Uuid;
use crate::entities::{oauth_account, oauth_account::Entity as OAuthAccount};

pub struct OAuthRepository;

impl OAuthRepository {
    pub async fn find_by_provider_and_id<C>(
        db: &C,
        provider: &str,
        provider_user_id: &str,
    ) -> Result<Option<oauth_account::Model>, DbErr>
    where
        C: ConnectionTrait,
    {
        OAuthAccount::find()
            .filter(oauth_account::Column::Provider.eq(provider))
            .filter(oauth_account::Column::ProviderUserId.eq(provider_user_id))
            .one(db)
            .await
    }

    pub async fn create<C>(
        db: &C,
        user_id: i64,
        provider: String,
        provider_user_id: String,
        provider_email: Option<String>,
        provider_name: Option<String>,
        provider_avatar: Option<String>,
        access_token: Option<String>,
        refresh_token: Option<String>,
        token_expires_at: Option<chrono::DateTime<Utc>>,
    ) -> Result<oauth_account::Model, DbErr>
    where
        C: ConnectionTrait,
    {
        let new_account = oauth_account::ActiveModel {
            id: NotSet,
            public_id: Set(Uuid::now_v7()),
            user_id: Set(user_id),
            provider: Set(provider),
            provider_user_id: Set(provider_user_id),
            provider_email: Set(provider_email),
            provider_name: Set(provider_name),
            provider_avatar: Set(provider_avatar),
            access_token: Set(access_token),
            refresh_token: Set(refresh_token),
            token_expires_at: Set(token_expires_at),
            created_at: Set(Utc::now()),
            updated_at: Set(Utc::now()),
        };

        new_account.insert(db).await
    }
}
