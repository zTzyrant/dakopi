use sea_orm::*;
use crate::entities::{user, role, user_role};
use crate::auth::SharedEnforcer;
use casbin::MgmtApi;
use uuid::Uuid;
use chrono::Utc;

pub async fn seed_super_user(db: &DatabaseConnection, enforcer: &SharedEnforcer) -> Result<(), String> {
    let username = "superadmin";
    let email = "super@dakopi.dev";
    let password = "superpassword123";

    // 1. Cek jika user sudah ada
    let exists = user::Entity::find()
        .filter(user::Column::Username.eq(username))
        .one(db)
        .await
        .map_err(|e| e.to_string())?;

    if exists.is_none() {
        println!("🚀 Creating Super User...");
        
        // Hash password menggunakan logic AuthService
        // Note: Karena method hash_password di AuthService private/internal, 
        // kita panggil manual logic-nya atau ubah visibility-nya. 
        // Untuk seeder kita buat simple saja dulu.
        let salt = argon2::password_hash::SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
        let argon2 = argon2::Argon2::default();
        let hashed_password = argon2::password_hash::PasswordHasher::hash_password(
            &argon2, password.as_bytes(), &salt
        ).map_err(|e| e.to_string())?.to_string();

        // Start Transaction
        let txn = db.begin().await.map_err(|e| e.to_string())?;

        // Simpan User
        let new_user = user::ActiveModel {
            public_id: Set(Uuid::now_v7()),
            username: Set(username.to_string()),
            email: Set(email.to_string()),
            password_hash: Set(hashed_password),
            created_at: Set(Utc::now()),
            updated_at: Set(Utc::now()),
            ..Default::default()
        };
        let user_model = new_user.insert(&txn).await.map_err(|e| e.to_string())?;

        // Cari Role Super
        let role_super = role::Entity::find()
            .filter(role::Column::Name.eq("super"))
            .one(&txn)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("Role 'super' not found")?;

        // Hubungkan User ke Role
        let link = user_role::ActiveModel {
            user_id: Set(user_model.id),
            role_id: Set(role_super.id),
        };
        link.insert(&txn).await.map_err(|e| e.to_string())?;

        // Tambahkan ke Casbin (g, uuid, super)
        {
            let mut e = enforcer.write().await;
            e.add_grouping_policy(vec![user_model.public_id.to_string(), "super".to_string()]).await
                .map_err(|e| e.to_string())?;
        }

        txn.commit().await.map_err(|e| e.to_string())?;
        println!("✅ Super User Created! (User: {}, Pass: {})", username, password);
    }

    Ok(())
}
