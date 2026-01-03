use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "users")]
pub struct Model {
    #[sea_orm(primary_key)] 
    pub id: i64,

    #[sea_orm(unique, index)]
    pub public_id: Uuid,

    // TAMBAHAN BARU
    // Kita tidak pasang attribute #[sea_orm(unique)] di sini
    // karena keunikan akan diatur manual oleh Migrasi (Partial Index)
    pub username: String, 
    pub email: String,
    
    #[serde(skip)]
    pub password_hash: String,

    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
    pub deleted_at: Option<DateTimeUtc>, // Soft Delete

    pub created_by: Option<Uuid>, 
    pub updated_by: Option<Uuid>,
    pub deleted_by: Option<Uuid>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}