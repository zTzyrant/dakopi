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
pub struct PolicyResponse {
    pub sub: String,
    pub obj: String,
    pub act: String,
}
