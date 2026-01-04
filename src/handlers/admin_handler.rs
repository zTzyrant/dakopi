use axum::{
    extract::State,
    response::IntoResponse,
};
use crate::config::AppState;
use crate::models::admin_model::CasbinPolicyRequest;
use crate::utils::api_response::ResponseBuilder;
use crate::utils::validated_wrapper::ValidatedJson;
use casbin::{MgmtApi};

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

// 2. List Semua Policy
pub async fn list_policies_handler(
    State(state): State<AppState>,
) -> impl IntoResponse {
    use crate::models::admin_model::PolicyResponse;
    let enforcer = state.enforcer.read().await;
    let policies = enforcer.get_all_policy();
    
    let formatted_policies: Vec<PolicyResponse> = policies.into_iter().map(|p| {
        PolicyResponse {
            sub: p.get(0).cloned().unwrap_or_default(),
            obj: p.get(1).cloned().unwrap_or_default(),
            act: p.get(2).cloned().unwrap_or_default(),
        }
    }).collect();
    
    ResponseBuilder::success("POLICIES_FETCHED", "Successfully fetched all policies", formatted_policies)
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
