use casbin::{MgmtApi};
use crate::auth::SharedEnforcer;

pub async fn seed_casbin_policies(enforcer: &SharedEnforcer) -> Result<(), casbin::Error> {
    let mut e = enforcer.write().await;

    // Define default policies
    let policies = vec![
        vec!["super".to_string(), "*".to_string(), "*".to_string()],
        vec!["admin".to_string(), "/api/admin/*".to_string(), "*".to_string()],
        vec!["user".to_string(), "/api/auth/profile".to_string(), "GET".to_string()],
    ];

    for policy in policies {
        if !e.has_policy(policy.clone()) {
            e.add_policy(policy).await?;
        }
    }

    println!("✅ Seeded Casbin Policies");
    Ok(())
}
