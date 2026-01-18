use redis::{Client, AsyncCommands};
use crate::config::Config;
use serde::{de::DeserializeOwned, Serialize};

#[derive(Clone)]
pub struct RedisService {
    client: Client,
}

impl RedisService {
    pub fn new(config: &Config) -> Self {
        let client = Client::open(config.redis_url.clone()).expect("Invalid Redis URL");
        Self { client }
    }

    pub async fn check_connection(&self) -> Result<(), String> {
        let mut con = self.client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| e.to_string())?;
        
        let _: () = con.set("dakopi_health_check", "ok").await.map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Set value ke Redis dengan expiry (detik)
    pub async fn set<V: Serialize>(&self, key: &str, value: V, expire_secs: u64) -> Result<(), String> {
        let mut con = self.client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| e.to_string())?;

        let json = serde_json::to_string(&value).map_err(|e| e.to_string())?;
        
        let _: () = con.set_ex(key, json, expire_secs).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Get value dari Redis
    pub async fn get<V: DeserializeOwned>(&self, key: &str) -> Option<V> {
        let mut con = self.client
            .get_multiplexed_async_connection()
            .await
            .ok()?;

        let result: Option<String> = con.get(key).await.ok();
        
        match result {
            Some(json) => serde_json::from_str(&json).ok(),
            None => None,
        }
    }

    /// Check if key exists
    pub async fn exists(&self, key: &str) -> bool {
        let mut con = match self.client.get_multiplexed_async_connection().await {
            Ok(c) => c,
            Err(_) => return false,
        };
        con.exists(key).await.unwrap_or(false)
    }
}
