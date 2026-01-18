use crate::config::Config;
use crate::services::redis_service::RedisService;
use chrono::{FixedOffset, Utc};
use reqwest::Client;
use serde::Serialize;

#[derive(Serialize)]
struct MailpitContact {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Email")]
    email: String,
}

#[derive(Serialize)]
struct MailpitPayload {
    #[serde(rename = "From")]
    from: MailpitContact,
    #[serde(rename = "To")]
    to: Vec<MailpitContact>,
    #[serde(rename = "Subject")]
    subject: String,
    #[serde(rename = "HTML")]
    html: String,
}

#[derive(Serialize)]
struct BrevoSender {
    name: String,
    email: String,
}

#[derive(Serialize)]
struct BrevoRecipient {
    email: String,
}

#[derive(Serialize)]
struct BrevoPayload {
    sender: BrevoSender,
    to: Vec<BrevoRecipient>,
    subject: String,
    #[serde(rename = "htmlContent")]
    html_content: String,
}

#[derive(Clone)]
pub struct EmailService {
    client: Client,
    redis: RedisService,
    is_production: bool,
    api_key: String,
    reset_hash_key: String,
    from_email: String,
    mailpit_url: String,
}

impl EmailService {
    pub fn new(config: &Config, redis: RedisService) -> Self {
        Self {
            client: Client::new(),
            redis,
            is_production: !config.brevo_api_key.is_empty(),
            api_key: config.brevo_api_key.clone(),
            reset_hash_key: config.reset_hash_key.clone(),
            from_email: config.smtp_from.clone(),
            mailpit_url: "http://localhost:8025/api/v1/send".to_string(),
        }
    }

    fn get_now_wita(&self) -> chrono::DateTime<FixedOffset> {
        let offset = FixedOffset::east_opt(8 * 3600).unwrap();
        Utc::now().with_timezone(&offset)
    }

    async fn check_and_increment_limit(&self) -> Result<bool, String> {
        if !self.is_production {
            return Ok(true);
        }

        let now = self.get_now_wita();
        let date_str = now.format("%Y-%m-%d").to_string();
        let key = format!("email_limit:{}", date_str);
        let limit_key = format!("email_limit:{}:limit", date_str);

        let current_count: i32 = self.redis.get::<i32>(&key).await.unwrap_or(0);
        let current_limit: i32 = self.redis.get::<i32>(&limit_key).await.unwrap_or(100);

        if current_count >= current_limit {
            return Err(format!(
                "Email limit reached ({} / {}). Please reset via API with your reset hash key.",
                current_count, current_limit
            ));
        }

        self.redis.set(&key, current_count + 1, 86400).await?;

        Ok(true)
    }

    pub async fn reset_limit(&self, secret: &str) -> Result<i32, String> {
        if secret != self.reset_hash_key {
            return Err("Invalid reset hash key".to_string());
        }

        let now = self.get_now_wita();
        let date_str = now.format("%Y-%m-%d").to_string();
        let limit_key = format!("email_limit:{}:limit", date_str);

        let current_limit: i32 = self.redis.get::<i32>(&limit_key).await.unwrap_or(100);

        if current_limit >= 300 {
            return Err("Hard limit 300 reached for today.".to_string());
        }

        let new_limit = (current_limit + 10).min(300);
        self.redis.set(&limit_key, new_limit, 86400).await?;

        Ok(new_limit)
    }

    pub async fn send_welcome_email(&self, to: &str, username: &str, verification_token: &str) -> Result<(), String> {
        self.check_and_increment_limit().await?;

        // TODO: Get Base URL from Config
        let verification_link = format!("http://localhost:3000/verify-email?token={}", verification_token);

        let subject = "Selamat Datang di Dakopi! Verifikasi Akun Anda";
        let html_body = format!(
            "<h3>Halo {}!</h3>
            <p>Akun kamu berhasil dibuat.</p>
            <p>Silakan klik link di bawah ini untuk memverifikasi email Anda:</p>
            <a href=\"{}\">Verifikasi Email</a>
            <p>Atau copy link berikut: {}</p>",
            username, verification_link, verification_link
        );

        if self.is_production {
            self.send_via_brevo(to, subject, &html_body).await
        } else {
            self.send_via_mailpit(to, subject, &html_body).await
        }
    }

    async fn send_via_brevo(&self, to: &str, subject: &str, html: &str) -> Result<(), String> {
        let payload = BrevoPayload {
            sender: BrevoSender {
                name: "Dakopi".to_string(),
                email: self.from_email.clone(),
            },
            to: vec![BrevoRecipient {
                email: to.to_string(),
            }],
            subject: subject.to_string(),
            html_content: html.to_string(),
        };

        let response = self
            .client
            .post("https://api.brevo.com/v3/smtp/email")
            .header("api-key", &self.api_key)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("Request error: {}", e))?;

        if response.status().is_success() {
            Ok(())
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(format!("Brevo API error: {}", error_text))
        }
    }

    async fn send_via_mailpit(&self, to: &str, subject: &str, html: &str) -> Result<(), String> {
        let payload = MailpitPayload {
            from: MailpitContact {
                name: "Dakopi Admin".into(),
                email: self.from_email.clone(),
            },
            to: vec![MailpitContact {
                name: "".into(),
                email: to.to_string(),
            }],
            subject: subject.to_string(),
            html: html.to_string(),
        };

        let response = self
            .client
            .post(&self.mailpit_url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("Mailpit request error: {}", e))?;

        if response.status().is_success() {
            Ok(())
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(format!("Mailpit Error: {}", error_text))
        }
    }
}
