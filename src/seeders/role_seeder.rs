use sea_orm::*;
use crate::entities::{role, role::Entity as Role};
use uuid::Uuid;

pub async fn seed_roles(db: &DatabaseConnection) -> Result<(), DbErr> {
    let roles = vec![
        ("super", "Super Administrator with full access"),
        ("admin", "Administrator with elevated access"),
        ("user", "Regular user with limited access"),
    ];

    for (name, desc) in roles {
        // Cek jika role sudah ada
        let exists = Role::find()
            .filter(role::Column::Name.eq(name))
            .one(db)
            .await?;

        if exists.is_none() {
            let new_role = role::ActiveModel {
                public_id: Set(Uuid::now_v7()),
                name: Set(name.to_string()),
                description: Set(Some(desc.to_string())),
                ..Default::default()
            };
            new_role.insert(db).await?;
            println!("✅ Seeded role: {}", name);
        }
    }

    Ok(())
}
