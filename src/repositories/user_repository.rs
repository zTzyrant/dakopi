use sea_orm::*;
use chrono::Utc;
use uuid::Uuid;
use crate::entities::{user, user::Entity as User};

pub struct UserRepository;

impl UserRepository {
    pub async fn find_active_by_login_id<C>(
        db: &C, 
        login_id: &str
    ) -> Result<Option<user::Model>, DbErr> 
    where C: ConnectionTrait {
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

    pub async fn find_active_duplicates<C>(
        db: &C,
        username: &str,
        email: &str
    ) -> Result<Vec<user::Model>, DbErr> 
    where C: ConnectionTrait {
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

    pub async fn create<C>(
        db: &C,
        username: String,
        email: String,
        password_hash: String
    ) -> Result<user::Model, DbErr> 
    where C: ConnectionTrait {
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

    pub async fn find_by_public_id_with_roles<C>(
        db: &C,
        public_id: Uuid
    ) -> Result<Option<(user::Model, Vec<crate::entities::role::Model>)>, DbErr>
    where C: ConnectionTrait {
        use crate::entities::{role};

        let user_with_roles = User::find()
            .filter(user::Column::PublicId.eq(public_id))
            .filter(user::Column::DeletedAt.is_null())
            .find_with_related(role::Entity)
            .all(db)
            .await?;

        Ok(user_with_roles.into_iter().next())
    }
}
