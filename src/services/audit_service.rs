use sea_orm::{DatabaseConnection, ActiveModelTrait, ActiveValue::Set};
use uuid::Uuid;
use chrono::Utc;
use serde_json::Value;
use crate::entities::audit_log;

pub struct AuditService;

impl AuditService {
    pub async fn log(
        db: &DatabaseConnection,
        user_id: Option<i64>,
        action: &str,
        resource: &str,
        resource_id: Option<String>,
        status: &str,
        error_message: Option<String>,
        metadata: Option<Value>,
        ip_address: Option<String>,
        user_agent: Option<String>,
        method: Option<String>,
        path: Option<String>,
    ) {
        let log = audit_log::ActiveModel {
            id: Set(Uuid::now_v7()),
            user_id: Set(user_id),
            action: Set(action.to_string()),
            resource: Set(resource.to_string()),
            resource_id: Set(resource_id),
            status: Set(status.to_string()),
            error_message: Set(error_message),
            metadata: Set(metadata),
            ip_address: Set(ip_address),
            user_agent: Set(user_agent),
            method: Set(method),
            path: Set(path),
            created_at: Set(Utc::now()),
        };

        // We spawn a task to avoid blocking the main request flow
        // and because logging failure shouldn't fail the request.
        let db = db.clone();
        tokio::spawn(async move {
            if let Err(e) = log.insert(&db).await {
                tracing::error!("Failed to create audit log: {}", e);
            }
        });
    }
}
