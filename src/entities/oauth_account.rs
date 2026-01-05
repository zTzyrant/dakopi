use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "oauth_accounts")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub user_id: i64,
    pub provider: String,
    pub provider_user_id: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub access_token: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub refresh_token: Option<String>,
    pub token_expires_at: Option<DateTimeUtc>,
    pub provider_email: Option<String>,
    pub provider_name: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub provider_avatar: Option<String>,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[allow(dead_code)]
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::user::Entity",
        from = "Column::UserId",
        to = "super::user::Column::Id",
        on_update = "NoAction",
        on_delete = "Cascade"
    )]
    User,
}

impl Related<super::user::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::User.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
