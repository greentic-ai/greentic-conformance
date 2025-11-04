use anyhow::{Result, anyhow};
use std::env;

/// Returns true when the environment flag is set to a truthy value.
/// Accepted truthy values: 1, true, yes (case-insensitive).
pub fn bool_flag(name: &str) -> bool {
    env::var(name)
        .map(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

/// Reads a required environment variable, trimming whitespace.
/// Provides a friendly error that keeps the secret value hidden.
pub fn required_env(name: &str) -> Result<String> {
    match env::var(name).map(|value| value.trim().to_string()) {
        Ok(value) if !value.is_empty() => Ok(value),
        _ => Err(anyhow!("environment variable {name} must be set")),
    }
}

/// Reads an environment variable but falls back to a default when missing or empty.
pub fn env_or_default(name: &str, default: &str) -> String {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.to_string())
}

/// Consolidated tenant context shared across conformance suites.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantContext {
    pub tenant_id: String,
    pub team_id: String,
    pub user_id: String,
}

impl TenantContext {
    pub fn detect() -> Result<Self> {
        let tenant_id = env_or_default("TENANT_ID", "local-tenant");
        let team_id = env_or_default("TEAM_ID", "local-team");
        let user_id = env_or_default("USER_ID", "local-user");

        // Fail fast inside CI contexts where the defaults should not be used.
        if bool_flag("CI") {
            if tenant_id == "local-tenant" {
                return Err(anyhow!("TENANT_ID must be set in CI"));
            }
            if team_id == "local-team" {
                return Err(anyhow!("TEAM_ID must be set in CI"));
            }
            if user_id == "local-user" {
                return Err(anyhow!("USER_ID must be set in CI"));
            }
        }

        Ok(Self {
            tenant_id,
            team_id,
            user_id,
        })
    }
}

/// Convenience helper that returns the OTEL endpoint if configured.
pub fn otel_exporter_endpoint() -> Option<String> {
    env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}
