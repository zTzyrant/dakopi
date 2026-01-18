use sea_orm::{DatabaseConnection, EntityTrait, ActiveValue::Set, ActiveModelTrait, QueryFilter, ColumnTrait};
use uuid::Uuid;
use chrono::Utc;
use slug::slugify;
use crate::entities::tag;

pub async fn seed_tags(db: &DatabaseConnection) -> Result<(), String> {
    let tags = vec!["Technology", "Programming", "Health", "Lifestyle", "Rust", "Web Development"];

    for name in tags {
        let exists = tag::Entity::find()
            .filter(tag::Column::Name.eq(name))
            .one(db)
            .await
            .map_err(|e| e.to_string())?;

        if exists.is_none() {
            let new_tag = tag::ActiveModel {
                public_id: Set(Uuid::now_v7()),
                name: Set(name.to_string()),
                slug: Set(slugify(name)),
                created_at: Set(Utc::now()),
                ..Default::default()
            };
            new_tag.insert(db).await.map_err(|e| e.to_string())?;
            tracing::info!("Seeded tag: {}", name);
        }
    }
    
    Ok(())
}