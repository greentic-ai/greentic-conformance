use anyhow::Result;
use oauth_mock::MockServer;
use rand::{
    distr::{Alphanumeric, SampleString},
    rng,
};
use reqwest::redirect::Policy;
use serde::Deserialize;
use serde_json::Value;
use std::io;

fn random_verifier() -> String {
    let mut rng = rng();
    Alphanumeric.sample_string(&mut rng, 64)
}

async fn mock_server_or_skip() -> Result<Option<MockServer>> {
    match MockServer::spawn_on_free_port().await {
        Ok(server) => Ok(Some(server)),
        Err(err) if binding_permission_denied(&err) => {
            eprintln!(
                "[skip] oauth-mock flow tests require permission to bind loopback sockets: {err}"
            );
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

fn binding_permission_denied(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(|io_err| io_err.kind() == io::ErrorKind::PermissionDenied)
    })
}

fn pkce_challenge(verifier: &str) -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest, Sha256};

    let hash = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hash)
}

#[tokio::test]
async fn discovery_and_jwks() -> Result<()> {
    let Some(server) = mock_server_or_skip().await? else {
        return Ok(());
    };
    let client = reqwest::Client::new();

    let discovery: Value = client
        .get(format!(
            "{}/.well-known/openid-configuration",
            server.base_url()
        ))
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(discovery["issuer"], server.issuer());

    let jwks: Value = client
        .get(format!("{}/jwks.json", server.base_url()))
        .send()
        .await?
        .json()
        .await?;
    assert!(jwks["keys"].is_array());
    Ok(())
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    id_token: Option<String>,
    token_type: String,
}

#[tokio::test]
async fn authorization_code_pkce_roundtrip() -> Result<()> {
    let Some(server) = mock_server_or_skip().await? else {
        return Ok(());
    };
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .build()?;

    let (client_id, client_secret) = server.default_client().await.unwrap();
    let verifier = random_verifier();
    let challenge = pkce_challenge(&verifier);

    let auth_response = client
        .get(format!("{}/authorize", server.base_url()))
        .query(&[
            ("response_type", "code"),
            ("client_id", client_id.as_str()),
            ("redirect_uri", "https://example.com/callback"),
            ("scope", "openid email profile"),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("state", "abc123"),
        ])
        .send()
        .await?;
    assert_eq!(auth_response.status(), reqwest::StatusCode::SEE_OTHER);
    let location = auth_response
        .headers()
        .get(reqwest::header::LOCATION)
        .unwrap()
        .to_str()?;
    let redirect = url::Url::parse(location)?;
    assert_eq!(
        redirect
            .query_pairs()
            .find(|(k, _)| k == "state")
            .map(|(_, v)| v.to_string()),
        Some("abc123".into())
    );
    let code = redirect
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string())
        .unwrap();

    let token: TokenResponse = client
        .post(format!("{}/token", server.base_url()))
        .basic_auth(&client_id, Some(&client_secret))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", "https://example.com/callback"),
            ("code_verifier", verifier.as_str()),
        ])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    assert_eq!(token.token_type, "Bearer");
    assert!(token.access_token.starts_with("ey"));
    assert!(token.id_token.is_some());
    assert!(token.refresh_token.is_some());

    validate_id_token(&server, token.id_token.as_ref().unwrap(), &client_id)?;
    Ok(())
}

fn validate_id_token(server: &MockServer, token: &str, aud: &str) -> Result<()> {
    #[derive(Debug, Deserialize, Clone)]
    struct Claims {
        iss: String,
        aud: String,
        exp: i64,
        iat: i64,
    }

    let jwk = &server.jwks()["keys"][0];
    let n = jwk["n"].as_str().unwrap();
    let e = jwk["e"].as_str().unwrap();
    let decoding = jsonwebtoken::DecodingKey::from_rsa_components(n, e)
        .expect("construct decoding key from RSA components");
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&[aud]);
    let token_data = jsonwebtoken::decode::<Claims>(token, &decoding, &validation)?;
    assert_eq!(token_data.claims.iss, server.issuer());
    assert_eq!(token_data.claims.aud, aud);
    assert!(token_data.claims.exp > token_data.claims.iat);
    Ok(())
}

#[tokio::test]
async fn client_credentials_roundtrip() -> Result<()> {
    let Some(server) = mock_server_or_skip().await? else {
        return Ok(());
    };
    let client = reqwest::Client::new();
    let (client_id, client_secret) = server.default_client().await.unwrap();

    let token: TokenResponse = client
        .post(format!("{}/token", server.base_url()))
        .basic_auth(&client_id, Some(&client_secret))
        .form(&[
            ("grant_type", "client_credentials"),
            ("scope", "openid profile"),
        ])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    assert!(token.id_token.is_none());
    assert!(token.refresh_token.is_none());
    assert!(token.access_token.starts_with("ey"));
    Ok(())
}

#[tokio::test]
async fn refresh_token_rotates() -> Result<()> {
    let Some(server) = mock_server_or_skip().await? else {
        return Ok(());
    };
    let client = reqwest::Client::new();
    let (client_id, client_secret) = server.default_client().await.unwrap();
    let verifier = random_verifier();
    let challenge = pkce_challenge(&verifier);

    let auth_response = reqwest::Client::builder()
        .redirect(Policy::none())
        .build()?
        .get(format!("{}/authorize", server.base_url()))
        .query(&[
            ("response_type", "code"),
            ("client_id", client_id.as_str()),
            ("redirect_uri", "https://example.com/callback"),
            ("scope", "openid email"),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await?;
    let location = auth_response
        .headers()
        .get(reqwest::header::LOCATION)
        .unwrap()
        .to_str()?;
    let code = url::Url::parse(location)?
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string())
        .unwrap();

    let initial: TokenResponse = client
        .post(format!("{}/token", server.base_url()))
        .basic_auth(&client_id, Some(&client_secret))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", "https://example.com/callback"),
            ("code_verifier", verifier.as_str()),
        ])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let refresh = initial.refresh_token.clone().unwrap();

    let refreshed: TokenResponse = client
        .post(format!("{}/token", server.base_url()))
        .basic_auth(&client_id, Some(&client_secret))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh.as_str()),
        ])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    assert_ne!(initial.access_token, refreshed.access_token);
    assert_ne!(initial.refresh_token, refreshed.refresh_token);

    let replay = client
        .post(format!("{}/token", server.base_url()))
        .basic_auth(&client_id, Some(&client_secret))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh.as_str()),
        ])
        .send()
        .await?;
    assert_eq!(replay.status(), reqwest::StatusCode::BAD_REQUEST);
    let err: Value = replay.json().await?;
    assert_eq!(err["error"], "invalid_grant");
    Ok(())
}

#[tokio::test]
async fn device_code_flow() -> Result<()> {
    let Some(server) = mock_server_or_skip().await? else {
        return Ok(());
    };
    let client = reqwest::Client::new();
    let (client_id, client_secret) = server.default_client().await.unwrap();

    let device: Value = client
        .post(format!("{}/device_authorization", server.base_url()))
        .form(&[
            ("client_id", client_id.as_str()),
            ("scope", "openid profile email"),
        ])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let device_code = device["device_code"].as_str().unwrap().to_string();
    let user_code = device["user_code"].as_str().unwrap().to_string();

    for _ in 0..2 {
        let pending = client
            .post(format!("{}/token", server.base_url()))
            .basic_auth(&client_id, Some(&client_secret))
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", device_code.as_str()),
            ])
            .send()
            .await?;
        assert_eq!(pending.status(), reqwest::StatusCode::BAD_REQUEST);
        let body: Value = pending.json().await?;
        assert!(
            body["error"] == "authorization_pending" || body["error"] == "slow_down",
            "unexpected error {body}"
        );
    }

    server.approve_device_code(&user_code).await?;

    let token: TokenResponse = client
        .post(format!("{}/token", server.base_url()))
        .basic_auth(&client_id, Some(&client_secret))
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", device_code.as_str()),
        ])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert!(token.access_token.starts_with("ey"));
    Ok(())
}

#[tokio::test]
async fn invalid_scope_rejected() -> Result<()> {
    let Some(server) = mock_server_or_skip().await? else {
        return Ok(());
    };
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .build()?;

    let (client_id, _) = server.default_client().await.unwrap();
    let response = client
        .get(format!("{}/authorize", server.base_url()))
        .query(&[
            ("response_type", "code"),
            ("client_id", client_id.as_str()),
            ("redirect_uri", "https://example.com/callback"),
            ("scope", "forbidden"),
            ("code_challenge", "abc"),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn jwks_rotates_per_instance() -> Result<()> {
    let Some(server_a) = mock_server_or_skip().await? else {
        return Ok(());
    };
    let kid_a = server_a.jwks()["keys"][0]["kid"]
        .as_str()
        .unwrap()
        .to_string();
    drop(server_a);

    let Some(server_b) = mock_server_or_skip().await? else {
        return Ok(());
    };
    let kid_b = server_b.jwks()["keys"][0]["kid"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(kid_a, kid_b);
    Ok(())
}
