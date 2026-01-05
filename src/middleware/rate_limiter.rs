use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use std::time::{Duration, Instant};
use axum::{
    middleware::Next,
    response::{IntoResponse, Response},
    extract::{Request, State},
    http::StatusCode,
};
use crate::utils::api_response::ResponseBuilder;
use crate::config::AppState; // Import AppState

pub struct RateLimiter {
    requests: Arc<RwLock<HashMap<String, Vec<Instant>>>>,
    max_requests: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            requests: Arc::new(RwLock::new(HashMap::new())),
            max_requests,
            window,
        }
    }
    
    /// Check if request is allowed
    pub async fn check_rate_limit(&self, identifier: &str) -> bool {
        let mut requests = self.requests.write().await;
        let now = Instant::now();
        
        // Clean old entries (lazy cleanup)
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        
        let entry = requests.entry(identifier.to_string()).or_insert_with(Vec::new);
        entry.retain(|&timestamp| timestamp > cutoff);
        
        if entry.len() >= self.max_requests {
            return false;
        }
        
        entry.push(now);
        true
    }
}

// Axum middleware implementation
pub async fn rate_limit_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let limiter = &state.rate_limiter;
    
    // Get identifier (IP address)
    // Note: In production behind a proxy (like Nginx/Cloudflare), use X-Forwarded-For properly.
    // For now we try to get it from header, fallback to "unknown"
    let identifier = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim())
        .unwrap_or("unknown")
        .to_string();
    
    if !limiter.check_rate_limit(&identifier).await {
        return ResponseBuilder::error::<()>(
            StatusCode::TOO_MANY_REQUESTS,
            "RATE_LIMIT_EXCEEDED",
            "Too many requests. Please try again later.",
        ).into_response();
    }
    
    next.run(request).await
}