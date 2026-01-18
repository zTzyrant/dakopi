use axum::{
    extract::State,
    response::IntoResponse,
};
use sea_orm::ConnectionTrait;
use crate::config::AppState;
use crate::models::admin_model::CasbinPolicyRequest;
use crate::utils::api_response::ResponseBuilder;
use crate::utils::validated_wrapper::ValidatedJson;
use casbin::{MgmtApi, CoreApi};

// 1. Tambah Policy
pub async fn add_policy_handler(
    State(state): State<AppState>,
    ValidatedJson(payload): ValidatedJson<CasbinPolicyRequest>,
) -> impl IntoResponse {
    let mut enforcer = state.enforcer.write().await;
    
    match enforcer.add_policy(vec![payload.sub.clone(), payload.obj.clone(), payload.act.clone()]).await {
        Ok(added) => {
            if added {
                ResponseBuilder::success("POLICY_ADDED", "Policy added successfully", payload)
            } else {
                ResponseBuilder::error(axum::http::StatusCode::CONFLICT, "POLICY_EXISTS", "Policy already exists")
            }
        },
        Err(e) => ResponseBuilder::error(axum::http::StatusCode::INTERNAL_SERVER_ERROR, "CASBIN_ERR", &e.to_string())
    }
}

// 2. List Semua Policy (Enhanced)
pub async fn list_policies_handler(
    State(state): State<AppState>,
) -> impl IntoResponse {
    use crate::models::admin_model::FullPolicyResponse;
    let mut enforcer = state.enforcer.write().await;
    
    // Force load to get latest
    let _ = enforcer.load_policy().await;

    let mut response_data = Vec::new();

    // Get 'p' policies
    let policies = enforcer.get_all_policy();
    for p in policies {
        response_data.push(FullPolicyResponse {
            ptype: "p".to_string(),
            v0: p.get(0).cloned().unwrap_or_default(),
            v1: p.get(1).cloned().unwrap_or_default(),
            v2: p.get(2).cloned().unwrap_or_default(),
            v3: p.get(3).cloned(),
            v4: p.get(4).cloned(),
            v5: p.get(5).cloned(),
        });
    }

    // Get 'g' policies (Grouping/Roles)
    let groupings = enforcer.get_all_grouping_policy();
    for g in groupings {
        response_data.push(FullPolicyResponse {
            ptype: "g".to_string(),
            v0: g.get(0).cloned().unwrap_or_default(), // User
            v1: g.get(1).cloned().unwrap_or_default(), // Role
            v2: g.get(2).cloned().unwrap_or_default(), // Domain (if any)
            v3: g.get(3).cloned(),
            v4: g.get(4).cloned(),
            v5: g.get(5).cloned(),
        });
    }
    
    ResponseBuilder::success("POLICIES_FETCHED", "Successfully fetched all policies and roles", response_data)
}

// 3. Hapus Policy
pub async fn remove_policy_handler(
    State(state): State<AppState>,
    ValidatedJson(payload): ValidatedJson<CasbinPolicyRequest>,
) -> impl IntoResponse {
    let mut enforcer = state.enforcer.write().await;
    
    match enforcer.remove_policy(vec![payload.sub, payload.obj, payload.act]).await {
        Ok(removed) => {
            if removed {
                ResponseBuilder::success("POLICY_REMOVED", "Policy removed successfully", ())
            } else {
                ResponseBuilder::error(axum::http::StatusCode::NOT_FOUND, "POLICY_NOT_FOUND", "Policy not found")
            }
        },
        Err(e) => ResponseBuilder::error(axum::http::StatusCode::INTERNAL_SERVER_ERROR, "CASBIN_ERR", &e.to_string())
    }
}

// 4. Cleanup Duplicates
pub async fn cleanup_policies_handler(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let db = &state.db;
    
    // Raw SQL for Postgres deduplication keeping the latest one (by ID)
    // Adjust logic if you want to keep oldest (change a.id < b.id to a.id > b.id)
    let sql = r#"
        DELETE FROM casbin_rule a 
        USING casbin_rule b 
        WHERE a.id < b.id 
          AND a.ptype = b.ptype 
          AND a.v0 = b.v0 
          AND a.v1 = b.v1 
          AND a.v2 = b.v2 
          AND a.v3 = b.v3 
          AND a.v4 = b.v4 
          AND a.v5 = b.v5
    "#;

    match db.execute(sea_orm::Statement::from_string(sea_orm::DatabaseBackend::Postgres, sql.to_string())).await {
        Ok(res) => {
            // Reload enforcer after DB cleanup
            let mut enforcer = state.enforcer.write().await;
            let _ = enforcer.load_policy().await;
            
            ResponseBuilder::success(
                "POLICIES_CLEANED", 
                &format!("Removed {} duplicate policies", res.rows_affected()), 
                serde_json::json!({ "deleted_count": res.rows_affected() })
            )
        },
        Err(e) => ResponseBuilder::error(axum::http::StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", &e.to_string())
    }
}