use axum::{
    extract::{State, Path, Query},
    response::IntoResponse,
    http::StatusCode,
    Extension,
};
use crate::config::AppState;
use crate::utils::api_response::ResponseBuilder;
use crate::utils::validated_wrapper::ValidatedJson;
use crate::services::article_service::ArticleService;
use crate::models::{auth_model::CurrentUser, article_model::*};
use crate::entities::user;
use sea_orm::{EntityTrait, QueryFilter, ColumnTrait}; // Added imports

pub async fn list_articles_handler(
    State(state): State<AppState>,
    Query(params): Query<ArticleFilterParams>,
) -> impl IntoResponse {
    match ArticleService::list_articles(&state.db, params).await {
        Ok(res) => ResponseBuilder::success("ARTICLES_FETCHED", "Success", res).into_response(),
        Err((status, code, msg)) => ResponseBuilder::error::<()>(status, code, &msg).into_response(),
    }
}

pub async fn get_article_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match ArticleService::get_article(&state.db, id).await {
        Ok(res) => ResponseBuilder::success("ARTICLE_FETCHED", "Success", res).into_response(),
        Err((status, code, msg)) => ResponseBuilder::error::<()>(status, code, &msg).into_response(),
    }
}

pub async fn create_article_handler(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    ValidatedJson(payload): ValidatedJson<CreateArticleRequest>,
) -> impl IntoResponse {
    // 1. Check Verification (Using PublicId lookup)
    let is_verified = if let Ok(Some(u)) = user::Entity::find()
        .filter(user::Column::PublicId.eq(user.id))
        .one(&state.db)
        .await 
    {
        u.email_verified.unwrap_or(false)
    } else {
        false
    };
    
    let is_admin = user.roles.contains(&"admin".to_string()) || user.roles.contains(&"super".to_string());

    if !is_verified && !is_admin {
        return ResponseBuilder::error::<()>(
            StatusCode::FORBIDDEN, 
            "ACCESS_DENIED", 
            "You must verify your email to create articles"
        ).into_response();
    }
    
    // Get DB ID (Int) from UUID
    let db_user_id = if let Ok(Some(u)) = user::Entity::find()
        .filter(user::Column::PublicId.eq(user.id))
        .one(&state.db).await 
    {
            u.id
        } else {
            return ResponseBuilder::error::<()>(StatusCode::UNAUTHORIZED, "USER_NOT_FOUND", "User not found").into_response();
        };

    match ArticleService::create_article(&state.db, db_user_id, is_admin, payload).await {
        Ok(res) => ResponseBuilder::created("ARTICLE_CREATED", "Article created", res).into_response(),
        Err((status, code, msg)) => ResponseBuilder::error::<()>(status, code, &msg).into_response(),
    }
}

pub async fn update_article_handler(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<uuid::Uuid>,
    ValidatedJson(payload): ValidatedJson<UpdateArticleRequest>,
) -> impl IntoResponse {
    let is_admin = user.roles.contains(&"admin".to_string()) || user.roles.contains(&"super".to_string());
    
    let db_user_id = if let Ok(Some(u)) = user::Entity::find()
        .filter(user::Column::PublicId.eq(user.id))
        .one(&state.db).await 
    {
            u.id
        } else {
            return ResponseBuilder::error::<()>(StatusCode::UNAUTHORIZED, "USER_NOT_FOUND", "User not found").into_response();
        };

    match ArticleService::update_article(&state.db, id, db_user_id, is_admin, payload).await {
        Ok(res) => ResponseBuilder::success("ARTICLE_UPDATED", "Article updated", res).into_response(),
        Err((status, code, msg)) => ResponseBuilder::error::<()>(status, code, &msg).into_response(),
    }
}

pub async fn list_tags_handler(
    State(state): State<AppState>,
) -> impl IntoResponse {
    match ArticleService::list_tags(&state.db).await {
        Ok(res) => ResponseBuilder::success("TAGS_FETCHED", "Success", res).into_response(),
        Err((status, code, msg)) => ResponseBuilder::error::<()>(status, code, &msg).into_response(),
    }
}

pub async fn create_tag_handler(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    ValidatedJson(payload): ValidatedJson<CreateTagRequest>,
) -> impl IntoResponse {
    let is_admin = user.roles.contains(&"admin".to_string()) || user.roles.contains(&"super".to_string());
    if !is_admin {
        return ResponseBuilder::error::<()>(StatusCode::FORBIDDEN, "ACCESS_DENIED", "Only admins can create tags").into_response();
    }

    match ArticleService::create_tag(&state.db, payload.name).await {
        Ok(res) => ResponseBuilder::created("TAG_CREATED", "Tag created successfully", res).into_response(),
        Err((status, code, msg)) => ResponseBuilder::error::<()>(status, code, &msg).into_response(),
    }
}

pub async fn delete_article_handler(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<uuid::Uuid>,
) -> impl IntoResponse {
    let is_admin = user.roles.contains(&"admin".to_string()) || user.roles.contains(&"super".to_string());
    
    let db_user_id = if let Ok(Some(u)) = user::Entity::find()
        .filter(user::Column::PublicId.eq(user.id))
        .one(&state.db).await 
    {
            u.id
        } else {
            return ResponseBuilder::error::<()>(StatusCode::UNAUTHORIZED, "USER_NOT_FOUND", "User not found").into_response();
        };

    match ArticleService::delete_article(&state.db, id, db_user_id, is_admin).await {
        Ok(_) => ResponseBuilder::success::<()>("ARTICLE_DELETED", "Article deleted", ()).into_response(),
        Err((status, code, msg)) => ResponseBuilder::error::<()>(status, code, &msg).into_response(),
    }
}
