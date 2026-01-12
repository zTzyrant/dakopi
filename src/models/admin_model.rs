use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Deserialize, Serialize, Validate)]
pub struct CasbinPolicyRequest {
    #[validate(length(min = 1))]
    pub sub: String, // Role/User
    #[validate(length(min = 1))]
    pub obj: String, // Path/Resource
    #[validate(length(min = 1))]
    pub act: String, // Method (GET, POST, *)
}

#[derive(Serialize)]
pub struct FullPolicyResponse {
    pub ptype: String, // p or g
    pub v0: String,    // sub
    pub v1: String,    // obj or group
    pub v2: String,    // act or domain
    pub v3: Option<String>,
    pub v4: Option<String>,
    pub v5: Option<String>,
}