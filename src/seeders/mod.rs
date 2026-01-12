pub mod role_seeder;
pub mod casbin_seeder;
pub mod user_seeder;
pub mod tag_seeder;

use sea_orm::DatabaseConnection;
use crate::auth::SharedEnforcer;

pub async fn run_seeders(db: &DatabaseConnection, enforcer: &SharedEnforcer) -> Result<(), String> {
    // 1. Seed Roles (Penting: urutan harus role dulu)
    role_seeder::seed_roles(db).await.map_err(|e| e.to_string())?;
    
    // 2. Seed Casbin Policies
    casbin_seeder::seed_casbin_policies(enforcer).await.map_err(|e| e.to_string())?;

    // 3. Seed Super User
    user_seeder::seed_super_user(db, enforcer).await?;

    // 4. Seed Tags
    tag_seeder::seed_tags(db).await?;
    
    Ok(())
}
