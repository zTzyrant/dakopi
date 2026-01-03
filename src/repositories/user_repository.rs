use sea_orm::*;
use chrono::Utc;
use uuid::Uuid;
use crate::entities::{user, user::Entity as User};

pub struct UserRepository;

impl UserRepository {
    // Find user by email or username (Active only)
    pub async fn find_active_by_login_id(
        db: &DatabaseConnection, 
        login_id: &str
    ) -> Result<Option<user::Model>, DbErr> {
        User::find()
            .filter(
                Condition::any()
                    .add(user::Column::Email.eq(login_id))
                    .add(user::Column::Username.eq(login_id))
            )
            .filter(user::Column::DeletedAt.is_null())
            .one(db)
            .await
    }

    // Check if user exists (for registration) - Returns LIST to identify what matches
    pub async fn find_active_duplicates(
        db: &DatabaseConnection,
        username: &str,
        email: &str
    ) -> Result<Vec<user::Model>, DbErr> {
         User::find()
        .filter(
            Condition::any()
                .add(user::Column::Email.eq(email))
                .add(user::Column::Username.eq(username))
        )
        .filter(user::Column::DeletedAt.is_null()) 
        .all(db)
        .await
    }

    // Create new user
    pub async fn create(
        db: &DatabaseConnection,
        username: String,
        email: String,
        password_hash: String
    ) -> Result<user::Model, DbErr> {
        let new_user = user::ActiveModel {
            id: NotSet,
            public_id: Set(Uuid::now_v7()),
            username: Set(username),
            email: Set(email),
            password_hash: Set(password_hash),
            created_at: Set(Utc::now()),
            updated_at: Set(Utc::now()),
            deleted_at: Set(None),
            created_by: Set(None),
            updated_by: Set(None),
            deleted_by: Set(None),
        };

        new_user.insert(db).await
    }
}