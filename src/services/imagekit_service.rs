use crate::config::Config;
use crate::models::imagekit_model::{ImageKitAuthTokenPayload, ImageKitUploadResponse};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use reqwest::Client;
use std::time::{SystemTime, UNIX_EPOCH};
use std::error::Error;

#[derive(Clone)]
pub struct ImageKitService {
    config: Config,
    client: Client,
}

impl ImageKitService {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            client: Client::new(),
        }
    }

    pub fn generate_auth_token(
        &self,
        file_name: String,
        use_unique_file_name: Option<bool>,
        folder: Option<String>,
    ) -> Result<String, Box<dyn Error>> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
        let exp = now + 600; // 10 minutes default

        let use_unique = use_unique_file_name.unwrap_or(true).to_string();

        let payload = ImageKitAuthTokenPayload {
            file_name,
            use_unique_file_name: use_unique,
            folder,
            iat: now,
            exp,
        };

        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(self.config.imagekit_public_key.clone());

        let token = encode(
            &header,
            &payload,
            &EncodingKey::from_secret(self.config.imagekit_private_key.as_bytes()),
        )?;

        Ok(token)
    }

    pub async fn upload_file(
        &self,
        file_data: Vec<u8>,
        file_name: String,
    ) -> Result<ImageKitUploadResponse, Box<dyn Error + Send + Sync>> {
        // Use reqwest::multipart::Form
        let part = reqwest::multipart::Part::bytes(file_data)
            .file_name(file_name.clone());
        
        // Don't chain file_name() directly if it returns Part, but here Part::bytes returns Part.
        
        let form = reqwest::multipart::Form::new()
            .part("file", part)
            .text("fileName", file_name)
            .text("useUniqueFileName", "true");

        let response = self
            .client
            .post("https://upload.imagekit.io/api/v2/files/upload") // Only upload endpoint
            .basic_auth(&self.config.imagekit_private_key, None::<&str>)
            .multipart(form)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(format!("ImageKit Upload Failed: {}", error_text).into());
        }

        let result = response.json::<ImageKitUploadResponse>().await?;
        Ok(result)
    }
}
