use std::collections::HashSet;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Minimal event provider descriptor used for conformance.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EventProvider {
    pub name: String,
    pub kind: String, // broker | source | sink
    #[serde(default)]
    pub topics: Vec<String>,
    #[serde(default)]
    pub metadata: Value,
}

/// Event flow node definition.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EventFlowNode {
    pub id: String,
    #[serde(alias = "type")]
    pub kind: String,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub topic: Option<String>,
}

/// Minimal event flow document.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EventFlow {
    pub id: String,
    pub nodes: Vec<EventFlowNode>,
}

/// Validates that event flows reference known providers and required metadata.
pub fn validate_event_flow(flow: &EventFlow, providers: &[EventProvider]) -> Result<()> {
    if flow.id.trim().is_empty() {
        bail!("event flow id must not be empty");
    }
    if flow.nodes.is_empty() {
        bail!("event flow '{}' must have at least one node", flow.id);
    }
    let provider_set: HashSet<_> = providers.iter().map(|p| p.name.as_str()).collect();
    for node in &flow.nodes {
        if node.id.trim().is_empty() {
            bail!("event flow '{}' contains node with empty id", flow.id);
        }
        if !node.kind.starts_with("event.") {
            bail!(
                "event flow '{}' node '{}' must be event.* kind",
                flow.id,
                node.id
            );
        }
        if node.provider.is_none() {
            bail!(
                "event flow '{}' node '{}' missing provider reference",
                flow.id,
                node.id
            );
        }
        let provider_name = node.provider.as_ref().unwrap();
        if !provider_set.contains(provider_name.as_str()) {
            bail!(
                "event flow '{}' node '{}' references unknown provider '{}'",
                flow.id,
                node.id,
                provider_name
            );
        }
        if node.topic.as_deref().unwrap_or("").trim().is_empty() {
            bail!(
                "event flow '{}' node '{}' must declare topic/stream",
                flow.id,
                node.id
            );
        }
    }
    Ok(())
}

/// Validates provider subscription lifecycle definitions.
pub fn validate_subscription_lifecycle(def: &SubscriptionLifecycle) -> Result<()> {
    if def.add.trim().is_empty() {
        bail!("subscription lifecycle missing add_subscription handler");
    }
    if def.update.trim().is_empty() {
        bail!("subscription lifecycle missing update_subscription handler");
    }
    if def.delete.trim().is_empty() {
        bail!("subscription lifecycle missing delete_subscription handler");
    }
    Ok(())
}

/// Subscription lifecycle config for a provider.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SubscriptionLifecycle {
    pub add: String,
    pub update: String,
    pub delete: String,
}

/// Validates a provider pack description includes required fields.
pub fn validate_provider(provider: &EventProvider) -> Result<()> {
    if provider.name.trim().is_empty() {
        bail!("provider name must not be empty");
    }
    if provider.kind.trim().is_empty() {
        bail!("provider kind must not be empty");
    }
    Ok(())
}
