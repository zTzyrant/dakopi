use axum::http::StatusCode;
use sea_orm::*;
use slug::slugify;
use uuid::Uuid;
use chrono::Utc;
use crate::entities::{article, article::Entity as Article, tag, article_tag, user};
use crate::models::article_model::*;

pub struct ArticleService;

impl ArticleService {
    pub async fn create_article(
        db: &DatabaseConnection,
        author_id: i64,
        _is_admin: bool,
        payload: CreateArticleRequest,
    ) -> Result<ArticleResponse, (StatusCode, &'static str, String)> {
        let txn = db.begin().await
             .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "TXN_ERR", "Transaction start failed".to_string()))?;

        // 2. Slug
        let slug = match payload.slug {
            Some(s) => Self::ensure_unique_slug(&txn, &s).await?, // Custom slug: just check unique, adds -1 if needed
            None => {
                let title_slug = slugify(&payload.title);
                // For auto-generated, we enforce date pattern
                Self::ensure_unique_slug(&txn, &title_slug).await?
            }
        };

        let article = article::ActiveModel {
            id: NotSet,
            public_id: Set(Uuid::now_v7()),
            title: Set(payload.title),
            slug: Set(slug),
            excerpt: Set(payload.excerpt),
            content: Set(payload.content),
            html_content: Set(None),
            status: Set(payload.status),
            visibility: Set(payload.visibility),
            published_at: Set(payload.published_at),
            featured_image: Set(payload.featured_image),
            author_id: Set(author_id),
            created_at: Set(Utc::now()),
            updated_at: Set(Utc::now()),
        };

        let saved = article.insert(&txn).await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, "DB_WRITE_ERR", format!("Failed to create article: {}", e)))?;

        if let Some(tag_uuids) = payload.tags {
            for tag_uuid in tag_uuids {
                let tag = tag::Entity::find()
                    .filter(tag::Column::PublicId.eq(tag_uuid))
                    .one(&txn).await
                    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Tag lookup failed".to_string()))?
                    .ok_or((StatusCode::BAD_REQUEST, "TAG_NOT_FOUND", format!("Tag with ID {} not found", tag_uuid)))?;

                let link = article_tag::ActiveModel {
                    article_id: Set(saved.id),
                    tag_id: Set(tag.id),
                };
                link.insert(&txn).await.ok();
            }
        }

        txn.commit().await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "TXN_COMMIT_ERR", "Transaction commit failed".to_string()))?;

        Self::get_article(db, saved.public_id.to_string()).await
    }

    pub async fn get_article(
        db: &DatabaseConnection,
        id_or_slug: String,
    ) -> Result<ArticleResponse, (StatusCode, &'static str, String)> {
        // For `get_article` (single):
        // 1. Fetch Article + Author
        let article_opt = if let Ok(uuid) = Uuid::parse_str(&id_or_slug) {
             Article::find().filter(article::Column::PublicId.eq(uuid)).find_also_related(user::Entity).one(db).await
        } else {
             Article::find().filter(article::Column::Slug.eq(id_or_slug)).find_also_related(user::Entity).one(db).await
        } .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Database error".to_string()))?;

        let (article, author_opt) = article_opt
             .ok_or((StatusCode::NOT_FOUND, "ARTICLE_NOT_FOUND", "Article not found".to_string()))?;
        
        let author = author_opt.ok_or((StatusCode::INTERNAL_SERVER_ERROR, "DATA_CORRUPT", "Article has no author".to_string()))?;

        // 2. Fetch Tags
        let tags = article.find_related(tag::Entity).all(db).await
             .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Failed to fetch tags".to_string()))?;

        Ok(Self::map_to_response(article, tags, author))
    }

    pub async fn list_articles(
        db: &DatabaseConnection,
        params: ArticleFilterParams,
    ) -> Result<ArticleListResponse, (StatusCode, &'static str, String)> {
        let page = params.page.unwrap_or(1);
        let limit = params.limit.unwrap_or(10);

        let mut query = Article::find();
        
        if let Some(status_str) = params.status {
            query = query.filter(article::Column::Status.eq(status_str));
        }

        if let Some(search) = params.search {
            query = query.filter(
                Condition::any()
                    .add(article::Column::Title.contains(&search))
                    .add(article::Column::Content.contains(&search))
            );
        }
        
        query = query.order_by_desc(article::Column::CreatedAt);

        let paginator = query.find_also_related(user::Entity).paginate(db, limit);
        let total = paginator.num_items().await.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Count failed".to_string()))?;
        let articles_with_authors = paginator.fetch_page(page - 1).await.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Fetch failed".to_string()))?;

        let mut data = Vec::new();
        for (art, author_opt) in articles_with_authors {
            let author = author_opt.ok_or((StatusCode::INTERNAL_SERVER_ERROR, "DATA_CORRUPT", "Article has no author".to_string()))?;
            let tags = art.find_related(tag::Entity).all(db).await.unwrap_or_default();
            data.push(Self::map_to_response(art, tags, author));
        }

        Ok(ArticleListResponse {
            data,
            meta: PaginationMeta { total, page, limit },
        })
    }

    pub async fn update_article(
        db: &DatabaseConnection,
        public_id: Uuid,
        user_id: i64,
        is_admin: bool,
        payload: UpdateArticleRequest,
    ) -> Result<ArticleResponse, (StatusCode, &'static str, String)> {
        let article = Article::find().filter(article::Column::PublicId.eq(public_id)).one(db).await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Database error".to_string()))?
            .ok_or((StatusCode::NOT_FOUND, "ARTICLE_NOT_FOUND", "Article not found".to_string()))?;

        if article.author_id != user_id && !is_admin {
            return Err((StatusCode::FORBIDDEN, "ACCESS_DENIED", "You are not the owner of this article".to_string()));
        }

        let txn = db.begin().await
             .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "TXN_ERR", "Transaction start failed".to_string()))?;

        let mut active: article::ActiveModel = article.into();

        if let Some(t) = payload.title { active.title = Set(t); }
        if let Some(s) = payload.slug {
            let slug = Self::ensure_unique_slug(&txn, &s).await?;
            active.slug = Set(slug);
        }
        if let Some(e) = payload.excerpt { active.excerpt = Set(Some(e)); }
        if let Some(c) = payload.content { active.content = Set(c); }
        if let Some(s) = payload.status { active.status = Set(s); }
        if let Some(v) = payload.visibility { active.visibility = Set(v); }
        if let Some(img) = payload.featured_image { active.featured_image = Set(Some(img)); }
        if let Some(p) = payload.published_at { active.published_at = Set(Some(p)); }
        
        active.updated_at = Set(Utc::now());

        let updated = active.update(&txn).await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, "DB_WRITE_ERR", format!("Failed to update article: {}", e)))?;

        if let Some(tag_uuids) = payload.tags {
            article_tag::Entity::delete_many()
                .filter(article_tag::Column::ArticleId.eq(updated.id))
                .exec(&txn).await
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_WRITE_ERR", "Failed to clear tags".to_string()))?;

            for tag_uuid in tag_uuids {
                let tag = tag::Entity::find().filter(tag::Column::PublicId.eq(tag_uuid)).one(&txn).await
                    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Tag lookup failed".to_string()))?
                    .ok_or((StatusCode::BAD_REQUEST, "TAG_NOT_FOUND", format!("Tag ID {} not found", tag_uuid)))?;

                let link = article_tag::ActiveModel {
                    article_id: Set(updated.id),
                    tag_id: Set(tag.id),
                };
                link.insert(&txn).await.ok();
            }
        }

        txn.commit().await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "TXN_COMMIT_ERR", "Transaction commit failed".to_string()))?;

        Self::get_article(db, updated.public_id.to_string()).await
    }

    pub async fn delete_article(
        db: &DatabaseConnection,
        public_id: Uuid,
        user_id: i64,
        is_admin: bool,
    ) -> Result<(), (StatusCode, &'static str, String)> {
        let article = Article::find().filter(article::Column::PublicId.eq(public_id)).one(db).await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Database error".to_string()))?
            .ok_or((StatusCode::NOT_FOUND, "ARTICLE_NOT_FOUND", "Article not found".to_string()))?;

        if article.author_id != user_id && !is_admin {
            return Err((StatusCode::FORBIDDEN, "ACCESS_DENIED", "You are not the owner of this article".to_string()));
        }

        article::Entity::delete_by_id(article.id).exec(db).await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_WRITE_ERR", "Failed to delete article".to_string()))?;

        Ok(())
    }

    pub async fn create_tag(
        db: &DatabaseConnection,
        name: String,
    ) -> Result<TagResponse, (StatusCode, &'static str, String)> {
        let slug = slugify(&name);
        
        let new_tag = tag::ActiveModel {
            id: NotSet,
            public_id: Set(Uuid::now_v7()),
            name: Set(name),
            slug: Set(slug),
            created_at: Set(Utc::now()),
        };

        let saved = new_tag.insert(db).await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, "DB_WRITE_ERR", format!("Failed to create tag: {}", e)))?;

        Ok(TagResponse {
            id: saved.public_id,
            name: saved.name,
            slug: saved.slug,
        })
    }

    pub async fn list_tags(db: &DatabaseConnection) -> Result<Vec<TagResponse>, (StatusCode, &'static str, String)> {
        let tags = tag::Entity::find().all(db).await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Failed to fetch tags".to_string()))?;
            
        Ok(tags.into_iter().map(|t| TagResponse {
            id: t.public_id,
            name: t.name,
            slug: t.slug,
        }).collect())
    }

        async fn ensure_unique_slug<C>(db: &C, title_slug: &str) -> Result<String, (StatusCode, &'static str, String)> 

        where C: ConnectionTrait {

            let today = Utc::now().format("%Y-%m-%d").to_string();

            let base_slug = format!("{}-{}", title_slug, today);

            

            let mut new_slug = base_slug.clone();

            let mut count = 1;

    

            while Article::find().filter(article::Column::Slug.eq(&new_slug)).one(db).await

                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB_ERR", "Slug check failed".to_string()))?

                .is_some() 

            {

                new_slug = format!("{}-{}", base_slug, count);

                count += 1;

            }

            Ok(new_slug)

        }

    fn map_to_response(model: article::Model, tags: Vec<tag::Model>, author: user::Model) -> ArticleResponse {
        ArticleResponse {
            id: model.public_id,
            title: model.title,
            slug: model.slug,
            excerpt: model.excerpt,
            content: model.content,
            status: model.status,
            visibility: model.visibility,
            tags: tags.into_iter().map(|t| TagResponse {
                id: t.public_id,
                name: t.name,
                slug: t.slug,
            }).collect(),
            featured_image: model.featured_image,
            author: ArticleAuthorResponse {
                id: author.public_id,
                username: author.username,
                avatar_url: author.avatar_url,
            },
            created_at: model.created_at,
            updated_at: model.updated_at,
        }
    }
}
