use axum::{
    extract::{State, Multipart},
    response::IntoResponse,
};
use axum::http::StatusCode;
use crate::config::AppState;
use crate::models::imagekit_model::{ImageKitAuthRequest, ImageKitTokenResponse, ImageKitUploadResponse};
use crate::utils::api_response::ResponseBuilder;
use crate::utils::validated_wrapper::ValidatedJson;


pub async fn get_auth_token_handler(
    State(state): State<AppState>,
    ValidatedJson(payload): ValidatedJson<ImageKitAuthRequest>,
) -> impl IntoResponse {
    match state.imagekit_service.generate_auth_token(
        payload.file_name,
        payload.use_unique_file_name,
        payload.folder,
    ) {
        Ok(token) => {
            ResponseBuilder::success(
                "IMAGEKIT_AUTH_SUCCESS",
                "Authentication token generated successfully",
                ImageKitTokenResponse { token },
            )
        },
        Err(e) => {
            tracing::error!("Failed to generate ImageKit token: {}", e);
            ResponseBuilder::error::<ImageKitTokenResponse>(
                StatusCode::INTERNAL_SERVER_ERROR,
                "IMAGEKIT_AUTH_ERROR",
                "Failed to generate authentication token",
            )
        }
    }
}

pub async fn upload_file_handler(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let mut file_data: Option<Vec<u8>> = None;
    let mut file_name: Option<String> = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        let name: String = field.name().unwrap_or("").to_string();
        
        if name == "file" {
            let content_type = field.content_type().unwrap_or("").to_string();
            let original_name = field.file_name().unwrap_or("unknown.webp").to_string();
            
            // Validate MIME type
            if content_type != "image/webp" {
                 return ResponseBuilder::error::<ImageKitUploadResponse>(
                    StatusCode::BAD_REQUEST,
                    "INVALID_FILE_TYPE",
                    "Only WebP images are allowed",
                );
            }

            // Read data
            match field.bytes().await {
                Ok(bytes) => {
                    // Validate Size (1MB = 1048576 bytes)
                    let size: usize = bytes.len();
                    if size > 1048576 {
                        return ResponseBuilder::error::<ImageKitUploadResponse>(
                            StatusCode::BAD_REQUEST,
                            "FILE_TOO_LARGE",
                            "File size exceeds 1MB limit",
                        );
                    }
                    file_data = Some(bytes.to_vec());
                    file_name = Some(original_name);
                },
                Err(e) => {
                     return ResponseBuilder::error::<ImageKitUploadResponse>(
                        StatusCode::BAD_REQUEST,
                        "UPLOAD_ERROR",
                        &format!("Failed to read file: {}", e),
                    );
                }
            }
        }
    }

    if let (Some(data), Some(name)) = (file_data, file_name) {
        match state.imagekit_service.upload_file(data, name).await {
            Ok(response) => {
                ResponseBuilder::success(
                    "UPLOAD_SUCCESS",
                    "File uploaded successfully",
                    response,
                )
            },
            Err(e) => {
                tracing::error!("ImageKit upload error: {}", e);
                ResponseBuilder::error::<ImageKitUploadResponse>(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "UPLOAD_FAILED",
                    &format!("Failed to upload to ImageKit: {}", e),
                )
            }
        }
    } else {
        ResponseBuilder::error::<ImageKitUploadResponse>(
            StatusCode::BAD_REQUEST,
            "MISSING_FILE",
            "No file found in the request",
        )
    }
}
