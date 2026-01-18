use crate::config::Config;
use aws_sdk_s3::{Client, config::Region};
use aws_config::BehaviorVersion;
use aws_sdk_s3::config::Credentials;
use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::primitives::ByteStream;
use std::error::Error;
use std::time::Duration;

#[derive(Clone)]
pub struct S3Service {
    config: Config,
    client: Client,
}

impl S3Service {
    pub async fn new(config: Config) -> Self {
        let credentials = Credentials::new(
            config.s3_access_key.clone(),
            config.s3_secret_key.clone(),
            None,
            None,
            "static"
        );
        
        let region = Region::new(config.s3_region.clone());
        
        let shared_config = aws_config::defaults(BehaviorVersion::latest())
            .region(region)
            .credentials_provider(credentials)
            .endpoint_url(config.s3_endpoint.clone())
            .load()
            .await;
            
        // Force path style for custom S3 endpoints (MinIO/Ceph/etc usually require this)
        let s3_config_builder = aws_sdk_s3::config::Builder::from(&shared_config)
            .force_path_style(true);

        let client = Client::from_conf(s3_config_builder.build());

        Self {
            config,
            client,
        }
    }

    pub async fn upload_file(
        &self,
        file_data: Vec<u8>,
        file_name: String,
        content_type: String
    ) -> Result<String, Box<dyn Error + Send + Sync>> {
        let bucket = &self.config.s3_bucket_name;
        
        // Try to add public-read ACL if possible, but standard logic first
        let result = self.client
            .put_object()
            .bucket(bucket)
            .key(&file_name)
            .body(file_data.into())
            .content_type(content_type)
            .send()
            .await;

        match result {
            Ok(_) => {
                let base = self.config.s3_endpoint.trim_end_matches('/');
                // Construct URL: endpoint/bucket/filename
                let url = format!("{}/{}/{}", base, bucket, file_name);
                Ok(url)
            }
            Err(e) => {
                let err_msg = e.into_service_error();
                tracing::error!("S3 Upload Error: {:?}", err_msg);
                Err(format!("S3 Upload Failed: {}", err_msg).into())
            }
        }
    }

    pub async fn get_presigned_url(
        &self,
        file_name: String
    ) -> Result<String, Box<dyn Error + Send + Sync>> {
        let bucket = &self.config.s3_bucket_name;
        
        let presigning_config = PresigningConfig::expires_in(Duration::from_secs(3600))?; // 1 Hour

        let presigned_req = self.client
            .get_object()
            .bucket(bucket)
            .key(&file_name)
            .presigned(presigning_config)
            .await?;

        Ok(presigned_req.uri().to_string())
    }

    pub async fn get_file_stream(
        &self,
        file_name: String
    ) -> Result<(ByteStream, String, i64), Box<dyn Error + Send + Sync>> {
        let bucket = &self.config.s3_bucket_name;
        
        let object = self.client
            .get_object()
            .bucket(bucket)
            .key(&file_name)
            .send()
            .await?;

        let content_type = object.content_type.unwrap_or("application/octet-stream".to_string());
        let content_length = object.content_length.unwrap_or(0);

        Ok((object.body, content_type, content_length))
    }
}
