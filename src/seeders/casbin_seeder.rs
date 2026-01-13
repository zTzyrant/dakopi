use crate::auth::SharedEnforcer;
use casbin::MgmtApi;

pub async fn seed_casbin_policies(enforcer: &SharedEnforcer) -> Result<(), casbin::Error> {
    let mut e = enforcer.write().await;

    // Define default policies
    let policies = vec![
        vec!["super".to_string(), "*".to_string(), "*".to_string()],
        vec![
            "super".to_string(),
            "account".to_string(),
            "bypass_verification".to_string(),
        ],
        vec![
            "admin".to_string(),
            "/api/admin/*".to_string(),
            "*".to_string(),
        ],
        vec![
            "admin".to_string(),
            "account".to_string(),
            "bypass_verification".to_string(),
        ],
        // User Policies
        vec![
            "user".to_string(),
            "/api/auth/profile".to_string(),
            "GET".to_string(),
        ],
        vec![
            "user".to_string(),
            "/api/auth/refresh".to_string(),
            "POST".to_string(),
        ],
        vec![
            "user".to_string(),
            "/api/auth/logout".to_string(),
            "POST".to_string(),
        ],
        vec![
            "user".to_string(),
            "/api/auth/2fa/setup".to_string(),
            "POST".to_string(),
        ],
        vec![
            "user".to_string(),
            "/api/auth/2fa/confirm".to_string(),
            "POST".to_string(),
        ],
        vec![
            "user".to_string(),
            "/api/auth/2fa/verify-login".to_string(),
            "POST".to_string(),
        ],
        vec![
            "user".to_string(),
            "/api/auth/2fa/disable".to_string(),
            "POST".to_string(),
        ],
        vec![
            "user".to_string(),
            "/api/articles".to_string(),
            "GET".to_string(),
        ], // List Articles
        vec![
            "user".to_string(),
            "/api/articles/*".to_string(),
            "GET".to_string(),
        ], // Get Article Detail
        vec![
            "user".to_string(),
            "/api/articles".to_string(),
            "POST".to_string(),
        ], // Create Article
        vec![
            "user".to_string(),
            "/api/articles/*".to_string(),
            "PUT".to_string(),
        ], // Update Article
        vec![
            "user".to_string(),
            "/api/articles/*".to_string(),
            "DELETE".to_string(),
        ], // Delete Article
        vec![
            "user".to_string(),
            "/api/articles/tags".to_string(),
            "GET".to_string(),
        ], // Tags
        vec![
            "user".to_string(),
            "/api/media".to_string(),
            "POST".to_string(),
        ], // Upload Media
        vec![
            "user".to_string(),
            "/api/imagekit/auth".to_string(),
            "GET".to_string(),
        ], // ImageKit Token
    ];

    for policy in policies {
        if !e.has_policy(policy.clone()) {
            e.add_policy(policy).await?;
        }
    }

    println!("✅ Seeded Casbin Policies");
    Ok(())
}
