use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};

pub type TenantId = String;
pub type TeamId = String;
pub type UserId = String;
pub type SessionId = String;
pub type CorrelationId = String;
pub type ThreadId = String;

const REQUIRED_OTEL_KEYS: &[&str] = &[
    "service.name",
    "greentic.pack.id",
    "greentic.pack.version",
    "greentic.flow.id",
    "greentic.node.id",
    "greentic.component.name",
    "greentic.component.version",
    "greentic.tenant.id",
    "greentic.team.id",
    "greentic.user.id",
    "greentic.session.id",
    "greentic.run.status",
    "greentic.capability",
    "greentic.artifacts.dir",
];

/// Asserts that the manifest contains a signature block with the required fields.
pub fn assert_signed_pack(manifest: &Value) -> Result<()> {
    let object = manifest
        .as_object()
        .ok_or_else(|| anyhow!("pack manifest must be a JSON object"))?;

    let signature = object
        .get("signature")
        .ok_or_else(|| anyhow!("pack manifest missing signature block"))?
        .as_object()
        .ok_or_else(|| anyhow!("signature block must be an object"))?;

    for field in ["type", "public_key", "signature"] {
        if !signature.contains_key(field) {
            return Err(anyhow!("signature block missing {field}"));
        }
    }

    Ok(())
}

/// Ensures that every message ID appears at most once, signalling idempotent sends.
pub fn assert_idempotent_send<I, S>(messages: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: Into<IdempotentMessage>,
{
    let mut seen = HashSet::new();
    for message in messages.into_iter() {
        let converted: IdempotentMessage = message.into();
        if !seen.insert(converted.id.clone()) {
            return Err(anyhow!(
                "message {} was sent more than once (expected idempotent send)",
                converted.id
            ));
        }
    }

    Ok(())
}

/// Confirms that span attributes expose the Greentic multi-tenant markers when telemetry is active.
pub fn assert_span_attrs(spans: &[SpanRecord]) -> Result<()> {
    if spans.is_empty() {
        return Err(anyhow!(
            "no spans captured; telemetry disabled or misconfigured"
        ));
    }

    for span in spans {
        assert_otel_attributes(&span.attributes).with_context(|| {
            format!("span '{}' missing required telemetry attributes", span.name)
        })?;
    }

    Ok(())
}

/// Validates the required OTEL span attributes are present and non-empty strings.
pub fn assert_otel_attributes(attrs: &HashMap<String, Value>) -> Result<()> {
    for key in REQUIRED_OTEL_KEYS {
        let value = attrs
            .get(*key)
            .ok_or_else(|| anyhow!("span missing required attribute '{}'", key))?;
        let as_str = value
            .as_str()
            .ok_or_else(|| anyhow!("span attribute '{}' must be a string (found {value})", key))?;
        if as_str.trim().is_empty() {
            bail!("span attribute '{}' must not be empty", key);
        }

        if *key == "greentic.pack.version"
            && let Err(err) = semver::Version::parse(as_str.trim())
        {
            bail!("span attribute 'greentic.pack.version' must be valid semver: {err}");
        }
    }

    Ok(())
}

/// Validates a tenant/team/user tuple is non-empty.
pub fn assert_valid_tenant_ctx(tenant_id: &str, team_id: &str, user_id: &str) -> Result<()> {
    ensure_non_empty("tenant_id", tenant_id)?;
    ensure_non_empty("team_id", team_id)?;
    ensure_non_empty("user_id", user_id)?;
    Ok(())
}

/// Validates session-related identifiers.
pub fn assert_valid_session_ids(
    session_id: &str,
    correlation_id: Option<&str>,
    thread_id: Option<&str>,
) -> Result<()> {
    ensure_non_empty("session_id", session_id)?;
    if let Some(correlation_id) = correlation_id {
        ensure_non_empty("correlation_id", correlation_id)?;
    }
    if let Some(thread_id) = thread_id {
        ensure_non_empty("thread_id", thread_id)?;
    }
    Ok(())
}

fn ensure_non_empty(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{name} must not be empty or whitespace");
    }
    Ok(())
}

/// Lightweight representation of a delivered message for idempotency checks.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdempotentMessage {
    pub id: String,
    pub payload_kind: Option<String>,
}

impl From<String> for IdempotentMessage {
    fn from(id: String) -> Self {
        Self {
            id,
            payload_kind: None,
        }
    }
}

impl From<&str> for IdempotentMessage {
    fn from(id: &str) -> Self {
        Self {
            id: id.to_string(),
            payload_kind: None,
        }
    }
}

impl From<(String, String)> for IdempotentMessage {
    fn from(value: (String, String)) -> Self {
        Self {
            id: value.0,
            payload_kind: Some(value.1),
        }
    }
}

impl From<(&str, &str)> for IdempotentMessage {
    fn from(value: (&str, &str)) -> Self {
        Self {
            id: value.0.to_string(),
            payload_kind: Some(value.1.to_string()),
        }
    }
}

/// Representation of a captured telemetry span emitted by the runner or downstream services.
#[derive(Debug, Clone, PartialEq)]
pub struct SpanRecord {
    pub name: String,
    pub attributes: HashMap<String, Value>,
}

impl SpanRecord {
    pub fn new(name: impl Into<String>, attributes: HashMap<String, Value>) -> Self {
        Self {
            name: name.into(),
            attributes,
        }
    }

    pub fn from_map(name: impl Into<String>, attributes: Map<String, Value>) -> Self {
        Self::new(name, attributes.into_iter().collect())
    }
}
