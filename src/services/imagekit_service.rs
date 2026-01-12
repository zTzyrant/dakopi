use crate::config::Config;
use crate::models::imagekit_model::{ImageKitAuthTokenPayload, ImageKitUploadResponse};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use reqwest::Client;
use std::time::{SystemTime, UNIX_EPOCH};
use std::error::Error;
use base64::{Engine as _, engine::general_purpose};

#[derive(Clone)]
pub struct ImageKitService {
    config: Config,
    client: Client,
}

impl ImageKitService {
    pub fn new(config: Config) -> Self {
        if config.imagekit_private_key.len() > 5 {
            let masked = format!("{}...", &config.imagekit_private_key[..5]);
            tracing::info!("ImageKit Initialized with Private Key: {}", masked);
        } else {
            tracing::warn!("ImageKit Private Key seems empty or invalid!");
        }

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
        // Debug Auth Header Construction
        // Manual construction to verify what's being sent
        let auth_str = format!("{}:", self.config.imagekit_private_key);
        let auth_b64 = general_purpose::STANDARD.encode(auth_str);
        
        tracing::info!("DEBUG IMAGEKIT: Private Key Length: {}", self.config.imagekit_private_key.len());
        tracing::info!("DEBUG IMAGEKIT: Constructed Auth Header would be: Basic {}", auth_b64);

        // Use reqwest::multipart::Form
        let part = reqwest::multipart::Part::bytes(file_data)
            .file_name(file_name.clone());
        
        let form = reqwest::multipart::Form::new()
            .part("file", part)
            .text("fileName", file_name)
            .text("useUniqueFileName", "true");

        // We use reqwest's built-in basic_auth which handles base64 encoding automatically.
        let response = self
            .client
            .post("https://upload.imagekit.io/api/v2/files/upload") 
            .basic_auth(&self.config.imagekit_private_key, Some(""))
            .multipart(form)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await?;
            tracing::error!("DEBUG IMAGEKIT: Status: {}, Body: {}", status, error_text);
            return Err(format!("ImageKit Upload Failed: {}", error_text).into());
        }

        let result = response.json::<ImageKitUploadResponse>().await?;
        Ok(result)
    }
}