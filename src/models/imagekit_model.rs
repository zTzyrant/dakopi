use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ImageKitUploadResponse {
    pub file_id: String,
    pub name: String,
    pub size: u64,
    pub version_info: VersionInfo,
    pub file_path: String,
    pub url: String,
    pub file_type: String,
    pub height: Option<u32>,
    pub width: Option<u32>,
    pub thumbnail_url: String,
    pub aitags: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VersionInfo {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct ImageKitAuthRequest {
    #[validate(length(min = 1))]
    #[serde(alias = "fileName")] // Allow both if needed, but camelCase preferred for JSON APIs usually
    pub file_name: String,
    pub use_unique_file_name: Option<bool>,
    pub folder: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ImageKitTokenResponse {
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ImageKitAuthTokenPayload {
    #[serde(rename = "fileName")]
    pub file_name: String,
    #[serde(rename = "useUniqueFileName")]
    pub use_unique_file_name: String, // Must be string "true"/"false" for ImageKit
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    pub iat: i64,
    pub exp: i64,
}
