use axum::http::StatusCode;
use image::ImageFormat;
use std::io::Cursor;
use uuid::Uuid;
use chrono::Utc;
use sea_orm::{DatabaseConnection, Set, ActiveModelTrait, EntityTrait, NotSet, ColumnTrait, QueryFilter, PaginatorTrait, QueryOrder};
use crate::config::AppState;
use crate::entities::media;
use crate::models::media_model::{MediaResponse, MediaListResponse};
use crate::models::article_model::PaginationMeta;
use crate::utils::nsfw_utils::{NsfwModel};
use std::path::Path;

pub struct MediaService;

impl MediaService {
    pub async fn upload_media(
        state: &AppState,
        uploader_id: i64, // Internal ID
        file_name: String,
        file_data: Vec<u8>,
        content_type: String,
    ) -> Result<MediaResponse, (StatusCode, &'static str, String)> {
        // 1. Validation (Size & Type)
        if file_data.len() > 5 * 1024 * 1024 { 
            return Err((StatusCode::BAD_REQUEST, "MEDIA_TOO_LARGE", "File size exceeds 5MB".to_string()));
        }

        if !content_type.starts_with("image/") {
             return Err((StatusCode::BAD_REQUEST, "MEDIA_INVALID_TYPE", "Only images are supported".to_string()));
        }

        // 2. NSFW Check
        if Self::is_nsfw(&file_data).await {
            return Err((StatusCode::BAD_REQUEST, "MEDIA_NSFW_DETECTED", "Image contains unsafe content".to_string()));
        }

        // 3. Convert to WebP
        let (webp_data, _width, _height) = Self::convert_to_webp(&file_data)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, "MEDIA_CONVERSION_ERR", format!("Failed to process image: {}", e)))?;

        // Fix Filename: Remove old extension, add .webp
        let name_without_ext = Path::new(&file_name)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("image");
        let new_filename = format!("{}.webp", name_without_ext);

        // 4. Upload to ImageKit
        let upload_result = state.imagekit_service.upload_file(webp_data.clone(), new_filename.clone()).await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, "STORAGE_UPLOAD_ERR", format!("Upload failed: {}", e)))?;

        // 5. Save to Database
        let public_id = Uuid::now_v7();
        let media_model = media::ActiveModel {
            id: NotSet, // Auto Increment
            public_id: Set(public_id),
            name: Set(upload_result.name),
            url: Set(upload_result.url.clone()),
            mime_type: Set("image/webp".to_string()),
            size: Set(webp_data.len() as i64),
            alt_text: Set(None),
            uploader_id: Set(uploader_id),
            created_at: Set(Utc::now()),
        };

        let saved = media_model.insert(&state.db).await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_WRITE_ERR", "Failed to save media record".to_string()))?;

        Ok(MediaResponse {
            id: saved.public_id,
            url: upload_result.url,
            name: new_filename,
            mime_type: "image/webp".to_string(),
            size: webp_data.len() as i64,
        })
    }

    pub async fn delete_media(
        db: &DatabaseConnection,
        public_id: Uuid,
        user_id: i64,
        is_admin: bool,
    ) -> Result<(), (StatusCode, &'static str, String)> {
        let media = media::Entity::find()
            .filter(media::Column::PublicId.eq(public_id))
            .one(db).await
             .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Database error".to_string()))?
             .ok_or((StatusCode::NOT_FOUND, "MEDIA_NOT_FOUND", "Media not found".to_string()))?;
             
        // Check Ownership
        if media.uploader_id != user_id && !is_admin {
            return Err((StatusCode::FORBIDDEN, "ACCESS_DENIED", "You are not the owner of this media".to_string()));
        }
        
        // Delete from DB
        media::Entity::delete_by_id(media.id).exec(db).await
             .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_WRITE_ERR", "Failed to delete media".to_string()))?;
             
        Ok(())
    }

    pub async fn list_media(
        db: &DatabaseConnection,
        page: u64,
        limit: u64,
    ) -> Result<MediaListResponse, (StatusCode, &'static str, String)> {
        let paginator = media::Entity::find()
            .order_by_desc(media::Column::CreatedAt)
            .paginate(db, limit);
            
        let total = paginator.num_items().await.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Count failed".to_string()))?;
        let items = paginator.fetch_page(page - 1).await.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Fetch failed".to_string()))?;
        
        let data = items.into_iter().map(|m| MediaResponse {
            id: m.public_id,
            url: m.url,
            name: m.name,
            mime_type: m.mime_type,
            size: m.size,
        }).collect();

        Ok(MediaListResponse { 
            data,
            meta: PaginationMeta { total, page, limit }
        })
    }

    // --- Helpers ---

    fn convert_to_webp(data: &[u8]) -> Result<(Vec<u8>, u32, u32), Box<dyn std::error::Error>> {
        let img = image::load_from_memory(data)?;
        let (width, height) = (img.width(), img.height());
        let mut buffer = Cursor::new(Vec::new());
        img.write_to(&mut buffer, ImageFormat::WebP)?;
        Ok((buffer.into_inner(), width, height))
    }

    async fn is_nsfw(data: &[u8]) -> bool {
        let data_clone = data.to_vec();
        let handle = tokio::task::spawn_blocking(move || {
            let img = match image::load_from_memory(&data_clone) {
                Ok(i) => i,
                Err(_) => return false,
            };
            let model_bytes = include_bytes!("../../assets/model.onnx"); 
            let model = match NsfwModel::load(model_bytes) {
                Ok(m) => m,
                Err(_) => return false,
            };
            match model.examine(&img) {
                Ok(results) => results.iter().any(|r| (r.label == "Porn" || r.label == "Hentai") && r.score > 0.8),
                Err(_) => false,
            }
        });
        handle.await.unwrap_or(false)
    }
}
