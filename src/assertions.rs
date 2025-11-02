use anyhow::{anyhow, Result};
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};

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
        let attrs = &span.attributes;
        for required in ["tenant", "session", "flow", "node", "provider"] {
            if !attrs.contains_key(required) {
                return Err(anyhow!(
                    "span {} missing required attribute {}",
                    span.name,
                    required
                ));
            }
        }
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
