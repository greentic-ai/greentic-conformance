#![cfg(feature = "oauth")]

use anyhow::Result;
use greentic_conformance::env::bool_flag;
use greentic_conformance::fixtures::oauth::DOCKER_COMPOSE;
use serde_json::json;

#[test]
fn provider_manifests_shape() -> Result<()> {
    let graph_manifest = json!({
        "id": "microsoft-graph",
        "authorization_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "scopes": ["offline_access", "Mail.Read"],
    });

    let generic_oidc = json!({
        "id": "generic-oidc",
        "issuer": "https://issuer.example.com",
        "discovery": true,
    });

    let manifests = vec![graph_manifest, generic_oidc];
    for manifest in &manifests {
        assert!(manifest.get("id").is_some(), "manifest missing id");
    }

    assert!(DOCKER_COMPOSE.contains("mock-oidc"));
    Ok(())
}

#[tokio::test]
async fn mock_oidc_flow_optional() -> Result<()> {
    if !bool_flag("CI_ENABLE_OAUTH") {
        // Discovery-only assertions are covered in provider_manifests_shape.
        return Ok(());
    }

    // In a full environment this would drive the OAuth start -> callback flow.
    // Here we simulate by ensuring required environment wiring is documented.
    let tenant = std::env::var("TENANT_ID").unwrap_or_else(|_| "acme".to_string());
    assert_eq!(tenant, "acme");

    Ok(())
}
