use std::env;

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::StatusCode;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
}

#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
}

#[derive(Debug, Deserialize)]
struct JwtClaims {
    aud: serde_json::Value,
}

fn decode_segment(segment: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(segment)
        .with_context(|| format!("invalid base64 segment: {segment}"))
}

fn decode_jwt_segment<T: for<'de> Deserialize<'de>>(segment: &str, label: &str) -> Result<T> {
    let bytes = decode_segment(segment)?;
    serde_json::from_slice(&bytes).with_context(|| format!("decode jwt {label}"))
}

fn get_env(key: &str) -> Result<String> {
    env::var(key).with_context(|| format!("missing environment variable {key}"))
}

#[tokio::test]
#[ignore]
async fn azure_client_credentials_smoke() -> Result<()> {
    let tenant_id = match env::var("AZURE_TENANT_ID") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => return Ok(()),
    };
    let client_id = get_env("AZURE_CLIENT_ID")?;
    let client_secret = get_env("AZURE_CLIENT_SECRET")?;

    let token_url = format!("https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token");
    let form = [
        ("grant_type", "client_credentials"),
        ("client_id", client_id.as_str()),
        ("client_secret", client_secret.as_str()),
        ("scope", "https://graph.microsoft.com/.default"),
    ];

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .context("build reqwest client")?;

    let token_resp = client
        .post(&token_url)
        .form(&form)
        .send()
        .await
        .context("request access token")?;

    assert_eq!(
        token_resp.status(),
        StatusCode::OK,
        "token endpoint returned error: {token_resp:?}"
    );

    let token_body: TokenResponse = token_resp.json().await.context("parse token response")?;
    assert_eq!(token_body.token_type.to_lowercase(), "bearer");

    let segments: Vec<&str> = token_body.access_token.split('.').collect();
    assert_eq!(segments.len(), 3, "expected JWT access token");

    let header: JwtHeader = decode_jwt_segment(segments[0], "header")?;
    assert_eq!(header.alg, "RS256");

    let claims: JwtClaims = decode_jwt_segment(segments[1], "claims")?;
    let aud_ok = match claims.aud {
        serde_json::Value::String(ref value) => value == "https://graph.microsoft.com",
        serde_json::Value::Array(ref arr) => arr.iter().any(|value| {
            value
                .as_str()
                .map(|s| s == "https://graph.microsoft.com")
                .unwrap_or(false)
        }),
        _ => false,
    };
    assert!(
        aud_ok,
        "access_token audience did not include Microsoft Graph: {:?}",
        claims.aud
    );

    let graph_resp = client
        .get("https://graph.microsoft.com/v1.0/organization?$select=id")
        .bearer_auth(&token_body.access_token)
        .send()
        .await
        .context("call Microsoft Graph organization endpoint")?;

    assert_eq!(
        graph_resp.status(),
        StatusCode::OK,
        "graph call failed: {graph_resp:?}"
    );

    Ok(())
}
