use serde::{Serialize, Deserialize};
use uuid::Uuid;
use crate::models::article_model::PaginationMeta;

#[derive(Serialize)]
pub struct MediaResponse {
    pub id: Uuid,
    pub url: String,
    pub name: String,
    pub mime_type: String,
    pub size: i64,
}

#[derive(Serialize)]
pub struct MediaListResponse {
    pub data: Vec<MediaResponse>,
    pub meta: PaginationMeta,
}

#[derive(Deserialize)]
pub struct MediaFilterParams {
    pub page: Option<u64>,
    pub limit: Option<u64>,
}