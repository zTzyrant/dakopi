use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;
use crate::entities::article::{ArticleStatus, ArticleVisibility};

#[derive(Deserialize, Validate)]
pub struct CreateArticleRequest {
    #[validate(length(min = 3, message = "Title is required and must be at least 3 chars"))]
    pub title: String,
    
    pub slug: Option<String>,
    pub excerpt: Option<String>,
    
    #[validate(length(min = 10, message = "Content is too short"))]
    pub content: String,
    
    #[serde(default = "default_status")]
    pub status: ArticleStatus,
    
    #[serde(default = "default_visibility")]
    pub visibility: ArticleVisibility,
    
    pub tags: Option<Vec<Uuid>>, // Tag Public IDs
    pub featured_image: Option<String>,
    pub published_at: Option<chrono::DateTime<chrono::Utc>>,
}

fn default_status() -> ArticleStatus { ArticleStatus::Draft }
fn default_visibility() -> ArticleVisibility { ArticleVisibility::Public }

#[derive(Deserialize, Validate)]
pub struct UpdateArticleRequest {
    pub title: Option<String>,
    pub slug: Option<String>,
    pub excerpt: Option<String>,
    pub content: Option<String>,
    pub status: Option<ArticleStatus>,
    pub visibility: Option<ArticleVisibility>,
    pub tags: Option<Vec<Uuid>>, // Tag Public IDs
    pub featured_image: Option<String>,
    pub published_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Serialize)]
pub struct TagResponse {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
}

#[derive(Deserialize, Validate)]
pub struct CreateTagRequest {
    #[validate(length(min = 1, message = "Tag name cannot be empty"))]
    pub name: String,
}

#[derive(Serialize)]
pub struct ArticleAuthorResponse {
    pub id: Uuid,
    pub username: String,
    pub avatar_url: Option<String>,
}

#[derive(Serialize)]
pub struct ArticleResponse {
    pub id: Uuid,
    pub title: String,
    pub slug: String,
    pub excerpt: Option<String>,
    pub content: String,
    pub status: ArticleStatus,
    pub visibility: ArticleVisibility,
    pub tags: Vec<TagResponse>,
    pub featured_image: Option<String>,
    pub author: ArticleAuthorResponse, 
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize)]
pub struct ArticleListResponse {
    pub data: Vec<ArticleResponse>,
    pub meta: PaginationMeta,
}

#[derive(Serialize)]
pub struct PaginationMeta {
    pub total: u64,
    pub page: u64,
    pub limit: u64,
}

#[derive(Deserialize)]
pub struct ArticleFilterParams {
    pub page: Option<u64>,
    pub limit: Option<u64>,
    pub status: Option<String>,
    pub search: Option<String>,
}