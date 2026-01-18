use axum::{
    extract::{State, Multipart},
    response::IntoResponse,
    Json,
};
use axum::http::StatusCode;
use crate::config::AppState;
use crate::models::s3_model::{S3UploadResponse, S3PresignedRequest, S3PresignedResponse};
use crate::utils::api_response::ResponseBuilder;
use uuid::Uuid;

pub async fn upload_file_handler(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let mut file_data: Option<Vec<u8>> = None;
    let mut file_name: Option<String> = None;
    let mut content_type: Option<String> = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        let name: String = field.name().unwrap_or("").to_string();
        
        if name == "file" {
            let received_type = field.content_type().unwrap_or("application/octet-stream").to_string();
            
            // Validate MIME type (Strict WebP)
            if received_type != "image/webp" {
                 return ResponseBuilder::error::<S3UploadResponse>(
                    StatusCode::BAD_REQUEST,
                    "INVALID_FILE_TYPE",
                    "Only WebP images are allowed",
                );
            }
            content_type = Some(received_type);
            
            let original_name = field.file_name().unwrap_or("unknown_file.webp").to_string();
            
            match field.bytes().await {
                Ok(bytes) => {
                    // Limit 1MB (1 * 1024 * 1024 bytes)
                    if bytes.len() > 1024 * 1024 {
                         return ResponseBuilder::error::<S3UploadResponse>(
                            StatusCode::BAD_REQUEST,
                            "FILE_TOO_LARGE",
                            "File size exceeds 1MB limit",
                        );
                    }
                    file_data = Some(bytes.to_vec());
                    file_name = Some(original_name);
                },
                Err(e) => {
                     return ResponseBuilder::error::<S3UploadResponse>(
                        StatusCode::BAD_REQUEST,
                        "UPLOAD_ERROR",
                        &format!("Failed to read file: {}", e),
                    );
                }
            }
        }
    }

    if let (Some(data), Some(name), Some(ctype)) = (file_data, file_name, content_type) {
        // Create unique filename: uuid-filename
        let unique_name = format!("{}-{}", Uuid::now_v7(), name);

        match state.s3_service.upload_file(data, unique_name.clone(), ctype).await {
            Ok(url) => {
                ResponseBuilder::success(
                    "UPLOAD_SUCCESS",
                    "File uploaded successfully",
                    S3UploadResponse {
                        url,
                        file_name: unique_name,
                    },
                )
            },
            Err(e) => {
                tracing::error!("S3 upload error: {}", e);
                ResponseBuilder::error::<S3UploadResponse>(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "UPLOAD_FAILED",
                    &format!("Failed to upload to S3: {}", e),
                )
            }
        }
    } else {
        ResponseBuilder::error::<S3UploadResponse>(
            StatusCode::BAD_REQUEST,
            "MISSING_FILE",
            "No file found in the request",
        )
    }
}

pub async fn get_presigned_url_handler(
    State(state): State<AppState>,
    Json(payload): Json<S3PresignedRequest>,
) -> impl IntoResponse {
    match state.s3_service.get_presigned_url(payload.file_name).await {
        Ok(url) => {
            ResponseBuilder::success(
                "PRESIGNED_URL_SUCCESS",
                "Presigned URL generated successfully",
                S3PresignedResponse { url },
            )
        },
        Err(e) => {
             tracing::error!("S3 presigned error: {}", e);
             ResponseBuilder::error::<S3PresignedResponse>(
                StatusCode::INTERNAL_SERVER_ERROR,
                "PRESIGNED_ERROR",
                &format!("Failed to generate URL: {}", e),
            )
        }
    }
}