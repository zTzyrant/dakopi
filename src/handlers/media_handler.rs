use axum::{
    extract::{State, Path, Multipart, Query},
    response::{IntoResponse},
    http::StatusCode,
    Extension,
};
use crate::config::AppState;
use crate::utils::api_response::ResponseBuilder;
use crate::services::media_service::MediaService;
use crate::models::auth_model::CurrentUser;
use crate::entities::user;
use sea_orm::{EntityTrait, QueryFilter, ColumnTrait};
use crate::utils::nsfw_utils::{NsfwModel, NsfwPrediction};
use crate::models::media_model::MediaFilterParams;

pub async fn check_nsfw_handler(
    mut multipart: Multipart,
) -> impl IntoResponse {
    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        if name == "file" {
            let data = match field.bytes().await {
                Ok(bytes) => bytes.to_vec(),
                Err(e) => return ResponseBuilder::error::<()>(StatusCode::BAD_REQUEST, "UPLOAD_ERR", &e.to_string()).into_response(),
            };

            let handle = tokio::task::spawn_blocking(move || -> Result<(bool, Vec<NsfwPrediction>), String> {
                let img = image::load_from_memory(&data).map_err(|e| e.to_string())?;
                let model_bytes = include_bytes!("../../assets/model.onnx");
                let model = NsfwModel::load(model_bytes).map_err(|e| e.to_string())?;
                let results = model.examine(&img).map_err(|e| e.to_string())?;
                
                // Logic Threshold sesuai media_service
                let is_nsfw = results.iter().any(|r| (r.label == "Porn" || r.label == "Hentai") && r.score > 0.8);
                
                Ok((is_nsfw, results))
            });

            return match handle.await {
                Ok(Ok((is_nsfw, results))) => ResponseBuilder::success(
                    "NSFW_CHECKED", 
                    "Analysis complete", 
                    serde_json::json!({
                        "is_nsfw": is_nsfw,
                        "verdict": if is_nsfw { "UNSAFE" } else { "SAFE" },
                        "predictions": results
                    })
                ).into_response(),
                Ok(Err(e)) => ResponseBuilder::error::<()>(StatusCode::INTERNAL_SERVER_ERROR, "ANALYSIS_ERR", &e).into_response(),
                Err(e) => ResponseBuilder::error::<()>(StatusCode::INTERNAL_SERVER_ERROR, "TASK_ERR", &e.to_string()).into_response(),
            };
        }
    }
    ResponseBuilder::error::<()>(StatusCode::BAD_REQUEST, "MISSING_FILE", "No file field").into_response()
}

pub async fn upload_media_handler(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    // 1. Strict Auth Check: Must be verified or Admin
    let is_verified = if let Ok(Some(u)) = user::Entity::find()
        .filter(user::Column::PublicId.eq(user.id))
        .one(&state.db)
        .await 
    {
        u.email_verified.unwrap_or(false)
    } else {
        false
    };
    
    let is_admin = user.roles.contains(&"admin".to_string()) || user.roles.contains(&"super".to_string());

    if !is_verified && !is_admin {
        return ResponseBuilder::error::<()>(
            StatusCode::FORBIDDEN, 
            "ACCESS_DENIED", 
            "Only verified users can upload media"
        ).into_response();
    }
    
    // Get DB ID (Int) from UUID
    let db_user_id = if let Ok(Some(u)) = user::Entity::find()
        .filter(user::Column::PublicId.eq(user.id))
        .one(&state.db).await 
    {
            u.id
    } else {
            return ResponseBuilder::error::<()>(StatusCode::UNAUTHORIZED, "USER_NOT_FOUND", "User not found").into_response();
    };

    // 2. Parse Multipart
    // We expect a single field "file"
    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        
        if name == "file" {
            let file_name = field.file_name().unwrap_or("upload").to_string();
            let content_type = field.content_type().unwrap_or("application/octet-stream").to_string();
            
            // Read Bytes
            let data = match field.bytes().await {
                Ok(bytes) => bytes.to_vec(),
                Err(e) => return ResponseBuilder::error::<()>(
                    StatusCode::BAD_REQUEST, 
                    "UPLOAD_ERR", 
                    &e.to_string()
                ).into_response(),
            };

            // Call Service
            match MediaService::upload_media(&state, db_user_id, file_name, data, content_type).await {
                Ok(media) => return ResponseBuilder::created("MEDIA_UPLOADED", "Upload successful", media).into_response(),
                Err((status, code, msg)) => return ResponseBuilder::error::<()>(status, code, &msg).into_response(),
            }
        }
    }

    ResponseBuilder::error::<()>(StatusCode::BAD_REQUEST, "MISSING_FILE", "No file field found").into_response()
}

pub async fn delete_media_handler(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<uuid::Uuid>,
) -> impl IntoResponse {
    // Only Admin can delete media freely? Or owner? Media table doesn't have owner_id in brief.
    // Assuming Admin only for now based on brief or if we add owner_id later.
    // Brief says: "Delete media asset". Let's restrict to Admin/Super for safety unless we track ownership.
    
    let is_admin = user.roles.contains(&"admin".to_string()) || user.roles.contains(&"super".to_string());
    
    // Get DB ID (Int) from UUID
    let db_user_id = if let Ok(Some(u)) = user::Entity::find()
        .filter(user::Column::PublicId.eq(user.id))
        .one(&state.db).await 
    {
            u.id
    } else {
            return ResponseBuilder::error::<()>(StatusCode::UNAUTHORIZED, "USER_NOT_FOUND", "User not found").into_response();
    };

    match MediaService::delete_media(&state.db, id, db_user_id, is_admin).await {
        Ok(_) => ResponseBuilder::success::<()>("MEDIA_DELETED", "Media deleted", ()).into_response(),
        Err((status, code, msg)) => ResponseBuilder::error::<()>(status, code, &msg).into_response(),
    }
}

pub async fn list_media_handler(
    State(state): State<AppState>,
    Query(params): Query<MediaFilterParams>,
) -> impl IntoResponse {
    let page = params.page.unwrap_or(1);
    let limit = params.limit.unwrap_or(10);

    match MediaService::list_media(&state.db, page, limit).await {
        Ok(res) => ResponseBuilder::success("MEDIA_FETCHED", "Success", res).into_response(),
        Err((status, code, msg)) => ResponseBuilder::error::<()>(status, code, &msg).into_response(),
    }
}