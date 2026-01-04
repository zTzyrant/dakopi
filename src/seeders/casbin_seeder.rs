use casbin::{MgmtApi};
use crate::auth::SharedEnforcer;

pub async fn seed_casbin_policies(enforcer: &SharedEnforcer) -> Result<(), casbin::Error> {
    let mut e = enforcer.write().await;

    // 1. Policy untuk SUPER (Akses Segalanya)
    // p, super, *, *
    e.add_policy(vec!["super".to_string(), "*".to_string(), "*".to_string()]).await?;

    // 2. Policy untuk ADMIN (Akses ke /api/admin/*)
    // p, admin, /api/admin/*, *
    e.add_policy(vec!["admin".to_string(), "/api/admin/*".to_string(), "*".to_string()]).await?;

    // 3. Policy untuk USER (Akses ke profile)
    // p, user, /api/auth/profile, GET
    e.add_policy(vec!["user".to_string(), "/api/auth/profile".to_string(), "GET".to_string()]).await?;

    println!("✅ Seeded Casbin Policies");
    Ok(())
}
