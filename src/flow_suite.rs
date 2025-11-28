use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_yaml_bw as serde_yaml;
use walkdir::WalkDir;

/// Options that tweak flow validation behaviour.
pub struct FlowValidationOptions {
    pub allowed_extensions: Vec<String>,
    pub require_schema: bool,
    validators: Vec<Arc<dyn FlowValidator>>,
}

impl Clone for FlowValidationOptions {
    fn clone(&self) -> Self {
        Self {
            allowed_extensions: self.allowed_extensions.clone(),
            require_schema: self.require_schema,
            validators: self.validators.clone(),
        }
    }
}

impl std::fmt::Debug for FlowValidationOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlowValidationOptions")
            .field("allowed_extensions", &self.allowed_extensions)
            .field("require_schema", &self.require_schema)
            .field("validators", &self.validators.len())
            .finish()
    }
}

impl Default for FlowValidationOptions {
    fn default() -> Self {
        Self {
            allowed_extensions: vec!["ygtc".into(), "yaml".into(), "yml".into(), "json".into()],
            require_schema: false,
            validators: Vec::new(),
        }
    }
}

/// Custom validator hook that can enforce additional flow invariants.
pub trait FlowValidator: Send + Sync {
    fn validate(&self, flow: &FlowDocument) -> Result<()>;
}

impl<T> FlowValidator for T
where
    T: Fn(&FlowDocument) -> Result<()> + Send + Sync,
{
    fn validate(&self, flow: &FlowDocument) -> Result<()> {
        (self)(flow)
    }
}

/// A validated flow document.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FlowDocument {
    pub id: String,
    #[serde(default)]
    pub r#type: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub schema_version: Option<String>,
    #[serde(rename = "$schema", default)]
    pub schema_ref: Option<String>,
    #[serde(default)]
    pub schema: Option<serde_json::Value>,
    pub nodes: Vec<FlowNode>,
}

/// A single node in a flow document.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FlowNode {
    pub id: String,
    #[serde(alias = "type")]
    pub kind: String,
    #[serde(default)]
    pub route: Option<NodeRoute>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

/// Routing targets for a node.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct NodeRoute {
    pub route: RouteKind,
    #[serde(default)]
    pub to: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RouteKind {
    FollowGraph,
    ToNode,
    ToNodes,
    ReplyToOrigin,
    EndFlow,
}

/// Report returned after validating a folder of flows.
#[derive(Debug, Clone)]
pub struct FlowValidationReport {
    pub root: PathBuf,
    pub flows: Vec<FlowDocument>,
}

/// Valid flow types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowType {
    Messaging,
    Events,
    Worker,
    DigitalWorker,
    Unknown,
}

/// Supported flow schema versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowSchemaVersion {
    V1,
}

/// Error returned when a flow declares an unknown schema version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownFlowSchemaVersion {
    pub found: String,
}

impl std::fmt::Display for UnknownFlowSchemaVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown flow schema version '{}'", self.found)
    }
}

impl std::error::Error for UnknownFlowSchemaVersion {}

/// Validates all flow documents inside the provided path using default options.
pub fn validate_flow_folder(path: &str) -> Result<FlowValidationReport> {
    FlowValidationOptions::default().validate_flow_folder(path)
}

impl FlowValidationOptions {
    /// Replaces the list of allowed extensions.
    pub fn with_allowed_extensions<I, S>(mut self, extensions: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allowed_extensions = extensions
            .into_iter()
            .map(|ext| ext.into().to_ascii_lowercase())
            .collect();
        self
    }

    /// Adds one extra extension (case-insensitive) to the allow list.
    pub fn allow_extension(mut self, extension: impl Into<String>) -> Self {
        let extension = extension.into().to_ascii_lowercase();
        if !self.allowed_extensions.iter().any(|ext| ext == &extension) {
            self.allowed_extensions.push(extension);
        }
        self
    }

    /// Whether a schema definition must be present in every flow.
    pub fn require_schema(mut self, required: bool) -> Self {
        self.require_schema = required;
        self
    }

    /// Allows flows to omit a schema definition.
    pub fn allow_missing_schema(self) -> Self {
        self.require_schema(false)
    }

    /// Registers an additional validator that will run on each flow document.
    pub fn add_validator<V>(mut self, validator: V) -> Self
    where
        V: FlowValidator + 'static,
    {
        self.validators.push(Arc::new(validator));
        self
    }

    /// Replaces any registered validators with the provided set.
    pub fn with_validators<I, V>(mut self, validators: I) -> Self
    where
        I: IntoIterator<Item = V>,
        V: FlowValidator + 'static,
    {
        self.validators = validators
            .into_iter()
            .map(|validator| Arc::new(validator) as Arc<dyn FlowValidator>)
            .collect();
        self
    }

    /// Validates all flow documents inside the provided path.
    pub fn validate_flow_folder(&self, path: impl AsRef<Path>) -> Result<FlowValidationReport> {
        let path = path.as_ref();
        if !path.exists() {
            bail!("flow path '{}' does not exist", path.display());
        }

        let mut flows = Vec::new();
        let mut any_files = false;

        for entry in WalkDir::new(path).into_iter().flatten() {
            if !entry.file_type().is_file() {
                continue;
            }

            let ext = entry
                .path()
                .extension()
                .and_then(|s| s.to_str())
                .map(|s| s.to_ascii_lowercase())
                .unwrap_or_default();

            if !self
                .allowed_extensions
                .iter()
                .any(|allowed| allowed == &ext)
            {
                continue;
            }

            any_files = true;

            let raw = fs::read_to_string(entry.path())
                .with_context(|| format!("failed to read flow file {}", entry.path().display()))?;
            let document = parse_flow_document(entry.path(), &raw)?;
            validate_flow(&document, self.require_schema)
                .with_context(|| format!("invalid flow document {}", entry.path().display()))?;
            for validator in &self.validators {
                validator.validate(&document).with_context(|| {
                    format!("custom validator failed for {}", entry.path().display())
                })?;
            }
            flows.push(document);
        }

        if !any_files {
            bail!(
                "no flow definitions found under '{}' (expected extensions: {:?})",
                path.display(),
                self.allowed_extensions
            );
        }

        Ok(FlowValidationReport {
            root: path.to_path_buf(),
            flows,
        })
    }
}

fn parse_flow_document(path: &Path, raw: &str) -> Result<FlowDocument> {
    if path
        .extension()
        .is_some_and(|ext| ext == "json" || ext == "JSON")
    {
        serde_json::from_str(raw).with_context(|| {
            format!(
                "failed to parse flow JSON {}",
                path.file_name()
                    .and_then(|p| p.to_str())
                    .unwrap_or("<unknown>")
            )
        })
    } else {
        serde_yaml::from_str(raw).or_else(|yaml_err| {
            serde_json::from_str(raw).map_err(|json_err| {
                anyhow::anyhow!(
                    "failed to parse flow file {} as YAML ({yaml_err}) or JSON ({json_err})",
                    path.display()
                )
            })
        })
    }
}

fn validate_flow(flow: &FlowDocument, require_schema: bool) -> Result<()> {
    detect_flow_schema_version(flow)?;
    if flow.id.trim().is_empty() {
        bail!("flow id must not be empty");
    }
    if require_schema && flow.schema.is_none() {
        bail!("flow '{}' must declare a schema", flow.id);
    }
    if flow.nodes.is_empty() {
        bail!("flow '{}' must declare at least one node", flow.id);
    }
    let mut seen_ids = HashSet::new();
    for node in &flow.nodes {
        if node.id.trim().is_empty() {
            bail!("flow '{}' contains a node with an empty id", flow.id);
        }
        if node.kind.trim().is_empty() {
            bail!(
                "flow '{}' node '{}' must declare a type/kind",
                flow.id,
                node.id
            );
        }
        if !seen_ids.insert(node.id.clone()) {
            bail!(
                "flow '{}' contains duplicate node id '{}'",
                flow.id,
                node.id
            );
        }
        if let Some(metadata) = &node.metadata {
            if !metadata.is_object() {
                bail!(
                    "flow '{}' node '{}' metadata must be a JSON object",
                    flow.id,
                    node.id
                );
            }
            if node.kind.starts_with("mcp.") {
                validate_mcp_metadata(flow, node, metadata)?;
            }
        }

        if let Some(route) = &node.route {
            validate_routing(flow, node, route)?;
        }
    }

    validate_flow_type(flow)?;

    Ok(())
}

/// Attempts to resolve the flow schema version from the document.
///
/// If no schema marker is present, v1 is assumed for backward compatibility.
pub fn detect_flow_schema_version(flow: &FlowDocument) -> Result<FlowSchemaVersion> {
    let hint = flow
        .schema_version
        .as_deref()
        .or(flow.schema_ref.as_deref());

    match hint.map(|raw| raw.trim().to_ascii_lowercase()) {
        None => Ok(FlowSchemaVersion::V1),
        Some(ref value) if value == "1" || value == "v1" || value == "flow.v1" => {
            Ok(FlowSchemaVersion::V1)
        }
        Some(value) => Err(UnknownFlowSchemaVersion { found: value }.into()),
    }
}

fn detect_flow_type(flow: &FlowDocument) -> FlowType {
    match flow
        .r#type
        .as_deref()
        .map(|v| v.trim().to_ascii_lowercase())
    {
        Some(ref t) if t == "messaging" => FlowType::Messaging,
        Some(ref t) if t == "events" => FlowType::Events,
        Some(ref t) if t == "worker" => FlowType::Worker,
        Some(ref t) if t == "digital_worker" || t == "digital-worker" => FlowType::DigitalWorker,
        _ => FlowType::Unknown,
    }
}

fn validate_flow_type(flow: &FlowDocument) -> Result<()> {
    match detect_flow_type(flow) {
        FlowType::Unknown => Ok(()), // soft validation; allow missing type for backward compatibility
        FlowType::Messaging => {
            for node in &flow.nodes {
                if node.kind.starts_with("event.") {
                    bail!(
                        "flow '{}' is messaging but contains event node '{}'",
                        flow.id,
                        node.id
                    );
                }
            }
            Ok(())
        }
        FlowType::Events => {
            for node in &flow.nodes {
                if !node.kind.starts_with("event.") {
                    bail!(
                        "flow '{}' is events but contains non-event node '{}'",
                        flow.id,
                        node.id
                    );
                }
            }
            Ok(())
        }
        FlowType::Worker => {
            let has_handoff = flow
                .nodes
                .iter()
                .any(|node| node.kind == "worker.handoff" || node.kind == "worker.invoke");
            if !has_handoff {
                bail!(
                    "flow '{}' is worker but missing worker handoff node",
                    flow.id
                );
            }
            Ok(())
        }
        FlowType::DigitalWorker => {
            let has_handoff = flow
                .nodes
                .iter()
                .any(|node| node.kind == "worker.handoff" || node.kind == "worker.invoke");
            if !has_handoff {
                bail!(
                    "flow '{}' is digital worker but missing worker handoff/invoke node",
                    flow.id
                );
            }
            let has_worker_id = flow.nodes.iter().any(|node| {
                node.metadata
                    .as_ref()
                    .and_then(|m| m.get("worker_id"))
                    .and_then(|v| v.as_str())
                    .map(|s| !s.trim().is_empty())
                    .unwrap_or(false)
            });
            if !has_worker_id {
                bail!(
                    "flow '{}' is digital worker but missing worker_id metadata",
                    flow.id
                );
            }
            Ok(())
        }
    }
}

fn validate_routing(flow: &FlowDocument, node: &FlowNode, routing: &NodeRoute) -> Result<()> {
    let id_set: HashSet<_> = flow.nodes.iter().map(|n| n.id.as_str()).collect();
    match routing.route {
        RouteKind::FollowGraph | RouteKind::ReplyToOrigin | RouteKind::EndFlow => Ok(()),
        RouteKind::ToNode => {
            let target = routing
                .to
                .as_ref()
                .and_then(|list| list.first())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "flow '{}' node '{}' route 'to_node' missing target",
                        flow.id,
                        node.id
                    )
                })?;
            if !id_set.contains(target.as_str()) {
                bail!(
                    "flow '{}' node '{}' routes to missing node '{}'",
                    flow.id,
                    node.id,
                    target
                );
            }
            Ok(())
        }
        RouteKind::ToNodes => {
            let targets = routing.to.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "flow '{}' node '{}' route 'to_nodes' missing targets",
                    flow.id,
                    node.id
                )
            })?;
            for target in targets {
                if !id_set.contains(target.as_str()) {
                    bail!(
                        "flow '{}' node '{}' routes to missing node '{}'",
                        flow.id,
                        node.id,
                        target
                    );
                }
            }
            Ok(())
        }
    }
}

fn validate_mcp_metadata(
    flow: &FlowDocument,
    node: &FlowNode,
    metadata: &serde_json::Value,
) -> Result<()> {
    let obj = metadata.as_object().ok_or_else(|| {
        anyhow::anyhow!(
            "flow '{}' node '{}' mcp metadata must be object",
            flow.id,
            node.id
        )
    })?;
    ensure_field(obj, "tool", flow, node)?;
    ensure_field(obj, "action", flow, node)?;
    Ok(())
}

fn ensure_field(
    obj: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    flow: &FlowDocument,
    node: &FlowNode,
) -> Result<()> {
    let value = obj
        .get(field)
        .and_then(|v| v.as_str())
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "flow '{}' node '{}' mcp node must declare {}",
                flow.id,
                node.id,
                field
            )
        })?;
    let _ = value;
    Ok(())
}
