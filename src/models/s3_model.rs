use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct S3UploadResponse {
    pub url: String,
    pub file_name: String,
}

#[derive(Deserialize)]
pub struct S3PresignedRequest {
    pub file_name: String,
}

#[derive(Serialize)]
pub struct S3PresignedResponse {
    pub url: String,
}