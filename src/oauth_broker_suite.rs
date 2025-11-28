use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

/// OAuth broker token request.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BrokerTokenRequest {
    pub tenant: String,
    pub resource_ref: String,
    pub scopes: Vec<String>,
}

/// OAuth broker token response.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BrokerTokenResponse {
    Token {
        access_token: String,
        expires_in: u64,
    },
    Error {
        error: String,
        error_description: Option<String>,
    },
}

/// Validates a broker token request for required fields.
pub fn validate_broker_request(req: &BrokerTokenRequest) -> Result<()> {
    if req.tenant.trim().is_empty() {
        bail!("broker request missing tenant");
    }
    if req.resource_ref.trim().is_empty() {
        bail!("broker request missing resource_ref");
    }
    if req.scopes.is_empty() || req.scopes.iter().any(|s| s.trim().is_empty()) {
        bail!("broker request scopes must be non-empty strings");
    }
    Ok(())
}

/// Validates a broker token response for success or structured error.
pub fn validate_broker_response(res: &BrokerTokenResponse) -> Result<()> {
    match res {
        BrokerTokenResponse::Token {
            access_token,
            expires_in,
        } => {
            if access_token.trim().is_empty() {
                bail!("broker response access_token must not be empty");
            }
            if *expires_in == 0 {
                bail!("broker response expires_in must be positive");
            }
        }
        BrokerTokenResponse::Error { error, .. } => {
            if error.trim().is_empty() {
                bail!("broker error must include non-empty error code");
            }
        }
    }
    Ok(())
}
