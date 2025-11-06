use std::env;

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

const DEFAULT_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform.read-only";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const TOKENINFO_URL: &str = "https://oauth2.googleapis.com/tokeninfo";

#[derive(Debug, Deserialize)]
struct ServiceAccount {
    client_email: String,
    private_key: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
}

#[derive(Debug, Serialize)]
struct JwtBearerClaims<'a> {
    iss: &'a str,
    scope: &'a str,
    aud: &'a str,
    iat: i64,
    exp: i64,
}

fn decode_service_account() -> Result<Option<ServiceAccount>> {
    let b64 = match env::var("GOOGLE_SA_JSON_B64") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => return Ok(None),
    };

    let decoded = general_purpose::STANDARD
        .decode(b64.trim())
        .or_else(|_| general_purpose::URL_SAFE_NO_PAD.decode(b64.trim()))
        .context("decode GOOGLE_SA_JSON_B64")?;
    let account: ServiceAccount =
        serde_json::from_slice(&decoded).context("parse service account JSON")?;
    Ok(Some(account))
}

fn load_scope() -> String {
    env::var("GOOGLE_SCOPE")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_SCOPE.to_string())
}

fn build_assertion(account: &ServiceAccount, scope: &str) -> Result<String> {
    let now = OffsetDateTime::now_utc();
    let iat = now.unix_timestamp();
    let exp = (now + Duration::minutes(10)).unix_timestamp();

    let claims = JwtBearerClaims {
        iss: &account.client_email,
        scope,
        aud: TOKEN_URL,
        iat,
        exp,
    };

    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("JWT".into());

    let key = EncodingKey::from_rsa_pem(account.private_key.as_bytes())
        .context("load service account private key")?;

    jsonwebtoken::encode(&header, &claims, &key).context("encode JWT bearer assertion")
}

#[tokio::test]
#[ignore]
async fn google_service_account_jwt_bearer_smoke() -> Result<()> {
    let Some(account) = decode_service_account()? else {
        return Ok(());
    };
    let scope = load_scope();
    let assertion = build_assertion(&account, &scope)?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .context("build reqwest client")?;

    let token_resp = client
        .post(TOKEN_URL)
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", assertion.as_str()),
        ])
        .send()
        .await
        .context("request Google access token")?;

    assert_eq!(
        token_resp.status(),
        StatusCode::OK,
        "token exchange failed: {token_resp:?}"
    );

    let token_body: TokenResponse = token_resp
        .json()
        .await
        .context("parse Google token response")?;
    assert_eq!(token_body.token_type.to_lowercase(), "bearer");

    let tokeninfo_resp = client
        .get(TOKENINFO_URL)
        .query(&[("access_token", token_body.access_token.as_str())])
        .send()
        .await
        .context("invoke tokeninfo endpoint")?;

    assert_eq!(
        tokeninfo_resp.status(),
        StatusCode::OK,
        "tokeninfo call failed: {tokeninfo_resp:?}"
    );

    Ok(())
}
