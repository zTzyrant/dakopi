use sea_orm::{entity::prelude::*, sea_query::StringLen};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
#[serde(rename_all = "lowercase")]
pub enum ArticleStatus {
    #[sea_orm(string_value = "draft")]
    Draft,
    #[sea_orm(string_value = "published")]
    Published,
    #[sea_orm(string_value = "archived")]
    Archived,
}

#[derive(Debug, Clone, PartialEq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
#[serde(rename_all = "lowercase")]
pub enum ArticleVisibility {
    #[sea_orm(string_value = "public")]
    Public,
    #[sea_orm(string_value = "private")]
    Private,
    #[sea_orm(string_value = "password_protected")]
    PasswordProtected,
}

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "articles")]
pub struct Model {
    #[sea_orm(primary_key)]
    #[serde(skip_serializing)]
    pub id: i64,
    #[sea_orm(unique, index)]
    pub public_id: Uuid,
    
    pub title: String,
    #[sea_orm(unique)]
    pub slug: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub excerpt: Option<String>,
    #[sea_orm(column_type = "Text")]
    pub content: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub html_content: Option<String>,
    
    pub status: ArticleStatus,
    pub visibility: ArticleVisibility,
    pub published_at: Option<DateTimeUtc>,
    // Tags removed, now via relation
    
    pub featured_image: Option<String>,
    pub author_id: i64,
    
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::user::Entity",
        from = "Column::AuthorId",
        to = "super::user::Column::Id",
        on_update = "NoAction",
        on_delete = "Cascade"
    )]
    User,
    #[sea_orm(has_many = "super::article_tag::Entity")]
    ArticleTag,
}

impl Related<super::user::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::User.def()
    }
}

impl Related<super::tag::Entity> for Entity {
    fn to() -> RelationDef {
        super::article_tag::Relation::Tag.def()
    }
    fn via() -> Option<RelationDef> {
        Some(super::article_tag::Relation::Article.def().rev())
    }
}

impl ActiveModelBehavior for ActiveModel {}
