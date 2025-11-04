use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use axum::{
    Json, Router,
    extract::{Form, Query, State},
    http::{StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use reqwest::{Client, Url, redirect::Policy as RedirectPolicy};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::{sync::oneshot, task::JoinHandle};

use crate::env;

/// Configuration for the OAuth suite.
#[derive(Debug, Clone)]
pub struct OAuthSuiteConfig {
    pub run_mock: bool,
    pub run_live: bool,
    pub live_providers: Vec<LiveProviderConfig>,
}

impl Default for OAuthSuiteConfig {
    fn default() -> Self {
        Self {
            run_mock: true,
            run_live: false,
            live_providers: Vec::new(),
        }
    }
}

impl OAuthSuiteConfig {
    /// Uses environment variables to determine which checks to run.
    ///
    /// - `CI_ENABLE_OAUTH` / `CI_ENABLE_OAUTH_MOCK` enable the mock provider flow.
    /// - `CI_ENABLE_OAUTH_LIVE` toggles live provider checks when credentials are present.
    /// - Provider-specific credentials follow the pattern:
    ///   - `OAUTH_<PROVIDER>_CLIENT_ID`
    ///   - `OAUTH_<PROVIDER>_CLIENT_SECRET`
    ///   - `OAUTH_<PROVIDER>_REDIRECT_URI`
    ///   - Optional overrides: `OAUTH_<PROVIDER>_AUTH_URL`, `OAUTH_<PROVIDER>_TOKEN_URL`, `OAUTH_<PROVIDER>_SCOPES`
    pub fn from_env() -> Self {
        let mock_disabled = env::bool_flag("CI_DISABLE_OAUTH_MOCK");
        let run_mock = if mock_disabled {
            false
        } else {
            env::bool_flag("CI_ENABLE_OAUTH")
                || env::bool_flag("CI_ENABLE_OAUTH_MOCK")
                || !env::bool_flag("CI")
        };
        let run_live = env::bool_flag("CI_ENABLE_OAUTH_LIVE");

        let mut live_providers = Vec::new();
        for provider in DEFAULT_LIVE_PROVIDERS {
            if let Some(config) = LiveProviderConfig::from_env(provider) {
                live_providers.push(config);
            }
        }

        Self {
            run_mock,
            run_live,
            live_providers,
        }
    }
}

/// Live provider configuration pulled from the environment.
#[derive(Debug, Clone)]
pub struct LiveProviderConfig {
    pub name: &'static str,
    pub authorization_url: String,
    pub token_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
}

impl LiveProviderConfig {
    fn from_env(definition: &'static LiveProviderDefinition) -> Option<Self> {
        let prefix = definition.env_prefix;
        let client_id = std::env::var(format!("{}_CLIENT_ID", prefix)).ok()?;
        let client_secret = std::env::var(format!("{}_CLIENT_SECRET", prefix)).ok()?;
        let redirect_uri = std::env::var(format!("{}_REDIRECT_URI", prefix)).ok()?;
        let authorization_url = std::env::var(format!("{}_AUTH_URL", prefix))
            .unwrap_or_else(|_| definition.authorization_url.to_string());
        let token_url = std::env::var(format!("{}_TOKEN_URL", prefix))
            .unwrap_or_else(|_| definition.token_url.to_string());
        let scopes = std::env::var(format!("{}_SCOPES", prefix))
            .map(|value| {
                value
                    .split_whitespace()
                    .map(|scope| scope.to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|_| definition.scopes.iter().map(|s| s.to_string()).collect());

        Some(Self {
            name: definition.name,
            authorization_url,
            token_url,
            client_id,
            client_secret,
            redirect_uri,
            scopes,
        })
    }
}

/// Report returned after running the OAuth suite.
#[derive(Debug, Clone)]
pub struct OAuthSuiteReport {
    pub outcomes: Vec<SuiteOutcome>,
}

/// Outcome of a particular OAuth check.
#[derive(Debug, Clone)]
pub struct SuiteOutcome {
    pub name: String,
    pub status: ConformanceStatus,
    pub details: Option<Value>,
}

impl SuiteOutcome {
    fn passed(name: impl Into<String>, details: Option<Value>) -> Self {
        Self {
            name: name.into(),
            status: ConformanceStatus::Passed,
            details,
        }
    }

    fn skipped(name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: ConformanceStatus::Skipped {
                reason: reason.into(),
            },
            details: None,
        }
    }
}

/// Status of an OAuth check.
#[derive(Debug, Clone)]
pub enum ConformanceStatus {
    Passed,
    Skipped { reason: String },
}

/// Executes the OAuth suite with the provided configuration.
pub async fn run_suite(config: OAuthSuiteConfig) -> Result<OAuthSuiteReport> {
    let mut outcomes = Vec::new();

    if config.run_mock {
        outcomes.push(run_mock_suite().await?);
    } else {
        outcomes.push(SuiteOutcome::skipped(
            "oauth:mock",
            "mock suite disabled by configuration",
        ));
    }

    for provider in &config.live_providers {
        if !config.run_live {
            outcomes.push(SuiteOutcome::skipped(
                format!("oauth:live:{}", provider.name),
                "CI_ENABLE_OAUTH_LIVE not enabled",
            ));
            continue;
        }

        match run_live_provider(provider).await {
            Ok(outcome) => outcomes.push(outcome),
            Err(err) if err.downcast_ref::<reqwest::Error>().is_some() => {
                outcomes.push(SuiteOutcome::skipped(
                    format!("oauth:live:{}", provider.name),
                    format!("live provider request failed: {err}"),
                ));
            }
            Err(err) => return Err(err),
        }
    }

    Ok(OAuthSuiteReport { outcomes })
}

async fn run_mock_suite() -> Result<SuiteOutcome> {
    let provider = MockOidcProvider::start().await?;
    let redirect_uri = provider.redirect_uri().to_string();
    let client = Client::builder()
        .redirect(RedirectPolicy::none())
        .timeout(Duration::from_secs(5))
        .build()?;

    let well_known_url = format!("{}/.well-known/openid-configuration", provider.issuer());
    let discovery: Value = client
        .get(&well_known_url)
        .send()
        .await
        .with_context(|| "failed to query mock discovery endpoint")?
        .json()
        .await
        .with_context(|| "failed to parse mock discovery response")?;

    assert_discovery_shape(&discovery)?;

    let authorize_url = format!("{}/authorize", provider.issuer());
    let authorize_response = client
        .get(&authorize_url)
        .query(&[
            ("response_type", "code"),
            ("client_id", provider.client_id()),
            ("redirect_uri", provider.redirect_uri()),
            ("scope", "openid profile email"),
            ("state", "state-123"),
        ])
        .send()
        .await
        .with_context(|| "failed to invoke mock authorize endpoint")?;

    if authorize_response.status() != StatusCode::SEE_OTHER {
        bail!(
            "expected 303 See Other from authorize; got {}",
            authorize_response.status()
        );
    }

    let location = authorize_response
        .headers()
        .get(header::LOCATION)
        .ok_or_else(|| anyhow!("authorize redirect missing location header"))?
        .to_str()
        .context("authorize redirect location not valid UTF-8")?;

    let redirect = Url::parse(location).context("failed to parse redirect location")?;
    let mut code = None;
    let mut state = None;
    for (key, value) in redirect.query_pairs() {
        if key == "code" {
            code = Some(value.to_string());
        } else if key == "state" {
            state = Some(value.to_string());
        }
    }

    let code = code.ok_or_else(|| anyhow!("redirect missing authorization code"))?;
    let state = state.ok_or_else(|| anyhow!("redirect missing state"))?;
    if state != "state-123" {
        bail!("state mismatch; expected state-123, got {state}");
    }

    let token_url = format!("{}/token", provider.issuer());
    let token_response: Value = client
        .post(&token_url)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("client_id", provider.client_id()),
            ("client_secret", provider.client_secret()),
        ])
        .send()
        .await
        .with_context(|| "failed to invoke mock token endpoint")?
        .json()
        .await
        .with_context(|| "failed to parse mock token response")?;

    provider.stop().await?;

    let details = json!({
        "discovery": discovery,
        "token": token_response,
    });

    Ok(SuiteOutcome::passed("oauth:mock", Some(details)))
}

async fn run_live_provider(provider: &LiveProviderConfig) -> Result<SuiteOutcome> {
    let client = Client::builder()
        .redirect(RedirectPolicy::limited(4))
        .timeout(Duration::from_secs(10))
        .build()?;

    let mut authorize = Url::parse(&provider.authorization_url)
        .with_context(|| format!("invalid authorization URL for {}", provider.name))?;

    {
        let mut pairs = authorize.query_pairs_mut();
        pairs.append_pair("response_type", "code");
        pairs.append_pair("client_id", &provider.client_id);
        pairs.append_pair("redirect_uri", &provider.redirect_uri);
        pairs.append_pair("scope", &provider.scopes.join(" "));
        pairs.append_pair("state", "greentic-conformance");
    }

    Url::parse(&provider.token_url)
        .with_context(|| format!("invalid token URL for {}", provider.name))?;

    // Fetching real providers may fail when network access is restricted.
    let response = client.get(authorize.clone()).send().await;

    match response {
        Ok(resp) => {
            if !(resp.status().is_success() || resp.status().is_redirection()) {
                bail!(
                    "authorization endpoint for {} returned unexpected status {}",
                    provider.name,
                    resp.status()
                );
            }
            Ok(SuiteOutcome::passed(
                format!("oauth:live:{}", provider.name),
                Some(json!({ "authorization_status": resp.status().as_u16() })),
            ))
        }
        Err(err) if err.is_connect() || err.is_timeout() => Ok(SuiteOutcome::skipped(
            format!("oauth:live:{}", provider.name),
            format!("network error contacting {}: {err}", provider.name),
        )),
        Err(err) => Err(err.into()),
    }
}

fn assert_discovery_shape(discovery: &Value) -> Result<()> {
    for field in [
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
    ] {
        if discovery.get(field).and_then(Value::as_str).is_none() {
            bail!("discovery document missing required field '{field}'");
        }
    }
    Ok(())
}

/// Definition of a supported live provider with defaults.
struct LiveProviderDefinition {
    name: &'static str,
    env_prefix: &'static str,
    authorization_url: &'static str,
    token_url: &'static str,
    scopes: &'static [&'static str],
}

const DEFAULT_LIVE_PROVIDERS: &[LiveProviderDefinition] = &[
    LiveProviderDefinition {
        name: "google",
        env_prefix: "OAUTH_GOOGLE",
        authorization_url: "https://accounts.google.com/o/oauth2/v2/auth",
        token_url: "https://oauth2.googleapis.com/token",
        scopes: &["openid", "email", "profile"],
    },
    LiveProviderDefinition {
        name: "microsoft",
        env_prefix: "OAUTH_MICROSOFT",
        authorization_url: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        token_url: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        scopes: &["openid", "offline_access", "User.Read"],
    },
    LiveProviderDefinition {
        name: "github",
        env_prefix: "OAUTH_GITHUB",
        authorization_url: "https://github.com/login/oauth/authorize",
        token_url: "https://github.com/login/oauth/access_token",
        scopes: &["read:user", "user:email"],
    },
];

/// Embedded mock OIDC provider for deterministic CI runs.
struct MockOidcProvider {
    issuer: String,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Result<(), hyper::Error>>>,
}

impl MockOidcProvider {
    async fn start() -> Result<Self> {
        let client_id = "mock-client".to_string();
        let client_secret = "mock-secret".to_string();
        let redirect_uri = "https://example.com/oauth/callback".to_string();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .context("failed to bind mock OIDC listener")?;
        let addr = listener
            .local_addr()
            .context("failed to obtain mock OIDC listener addr")?;
        let issuer = format!("http://{}", addr);

        let state = ProviderState {
            issuer: issuer.clone(),
            client_id: client_id.clone(),
            client_secret: client_secret.clone(),
            redirect_uri: redirect_uri.clone(),
            code: "mock-code".to_string(),
        };

        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let app = Router::new()
            .route("/.well-known/openid-configuration", get(well_known))
            .route("/authorize", get(authorize))
            .route("/token", post(token))
            .route("/jwks", get(jwks))
            .with_state(state);

        let task = tokio::spawn(
            axum::serve(listener, app).with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            }),
        );

        Ok(Self {
            issuer,
            client_id,
            client_secret,
            redirect_uri,
            shutdown: Some(shutdown_tx),
            task: Some(task),
        })
    }

    fn issuer(&self) -> &str {
        &self.issuer
    }

    fn client_id(&self) -> &str {
        &self.client_id
    }

    fn client_secret(&self) -> &str {
        &self.client_secret
    }

    fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    async fn stop(mut self) -> Result<()> {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.task.take() {
            task.await
                .context("mock OIDC server task panicked")?
                .context("mock OIDC server failed")?;
        }
        Ok(())
    }
}

impl Drop for MockOidcProvider {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

#[derive(Clone)]
struct ProviderState {
    issuer: String,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    code: String,
}

#[derive(Debug, Deserialize)]
struct AuthorizeRequest {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: Option<String>,
    state: Option<String>,
}

async fn well_known(State(state): State<ProviderState>) -> impl IntoResponse {
    Json(json!({
        "issuer": state.issuer,
        "authorization_endpoint": format!("{}/authorize", state.issuer),
        "token_endpoint": format!("{}/token", state.issuer),
        "jwks_uri": format!("{}/jwks", state.issuer),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }))
}

async fn authorize(
    State(state): State<ProviderState>,
    Query(params): Query<AuthorizeRequest>,
) -> impl IntoResponse {
    if params.client_id != state.client_id {
        return (StatusCode::BAD_REQUEST, "invalid client_id").into_response();
    }
    if params.redirect_uri != state.redirect_uri {
        return (StatusCode::BAD_REQUEST, "invalid redirect_uri").into_response();
    }
    if params.response_type != "code" {
        return (StatusCode::BAD_REQUEST, "unsupported response_type").into_response();
    }

    let state_param = params.state.unwrap_or_default();
    let location = format!(
        "{}?code={}&state={}",
        state.redirect_uri, state.code, state_param
    );

    (StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response()
}

#[derive(Debug, Deserialize)]
struct TokenRequest {
    grant_type: String,
    code: String,
    redirect_uri: String,
    client_id: String,
    client_secret: String,
}

async fn token(
    State(state): State<ProviderState>,
    Form(params): Form<TokenRequest>,
) -> impl IntoResponse {
    if params.grant_type != "authorization_code" {
        return (StatusCode::BAD_REQUEST, "unsupported grant_type").into_response();
    }
    if params.code != state.code {
        return (StatusCode::BAD_REQUEST, "invalid authorization code").into_response();
    }
    if params.client_id != state.client_id || params.client_secret != state.client_secret {
        return (StatusCode::BAD_REQUEST, "invalid client credentials").into_response();
    }
    if params.redirect_uri != state.redirect_uri {
        return (StatusCode::BAD_REQUEST, "redirect_uri mismatch").into_response();
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs();
    let token = json!({
        "token_type": "Bearer",
        "expires_in": 3600,
        "access_token": format!("mock-access-token-{}", now),
        "refresh_token": "mock-refresh-token",
        "id_token": format!("mock-id-token-{}", now),
    });

    (StatusCode::OK, Json(token)).into_response()
}

async fn jwks(State(state): State<ProviderState>) -> impl IntoResponse {
    Json(json!({
        "keys": [{
            "kty": "RSA",
            "kid": "mock-key",
            "alg": "RS256",
            "use": "sig",
            "n": "mock-modulus",
            "e": "AQAB",
            "issuer": state.issuer,
        }]
    }))
}
