use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use crate::config::AppState;
use crate::utils::api_response::ResponseBuilder;
use casbin::prelude::*;

pub async fn rbac_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, Response> {
    // 1. Ambil User ID/Role dari Extension (Asumsi sudah lewat JWT Auth)
    // Untuk demo, kita ambil role "user" jika belum ada login. 
    // Nanti ini harus diambil dari JWT Claims.
    let user_sub = "user"; 
    
    // 2. Ambil Path dan Method
    let path = req.uri().path().to_string();
    let method = req.method().to_string();

    // 3. Cek Permission via Casbin
    let enforcer = state.enforcer.read().await;
    if enforcer.enforce((user_sub, &path, &method)).unwrap_or(false) {
        Ok(next.run(req).await)
    } else {
        Err(ResponseBuilder::error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN_ACCESS",
            "You do not have permission to access this resource"
        ).into_response())
    }
}
