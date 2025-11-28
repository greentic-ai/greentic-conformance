use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_yaml_bw as serde_yaml;

/// Adapter that knows how to interrogate a pack component at runtime.
pub trait PackRuntimeAdapter: Send + Sync {
    fn list_flows(&self, component_path: &Path) -> Result<Vec<String>>;
}

impl<T> PackRuntimeAdapter for T
where
    T: Fn(&Path) -> Result<Vec<String>> + Send + Sync,
{
    fn list_flows(&self, component_path: &Path) -> Result<Vec<String>> {
        (self)(component_path)
    }
}

/// Configuration knobs for pack verification.
#[derive(Clone)]
pub struct PackSuiteOptions {
    /// Optional manifest path override.
    pub manifest_override: Option<PathBuf>,
    /// Require at least one flow to be exported.
    pub require_flows: bool,
    /// Optional runtime adapter used to query the component for its exports.
    pub runtime_adapter: Option<Arc<dyn PackRuntimeAdapter>>,
    /// Fail verification if runtime exports diverge from the manifest.
    pub require_runtime_match: bool,
    /// Fail when the manifest does not contain a signature block.
    pub require_signature: bool,
    /// Whether referenced flow/component paths must exist on disk.
    pub require_artifacts_exist: bool,
    /// Require supply-chain metadata such as SBOM/attestations.
    pub require_supply_chain: bool,
}

impl Default for PackSuiteOptions {
    fn default() -> Self {
        Self {
            manifest_override: None,
            require_flows: true,
            runtime_adapter: None,
            require_runtime_match: true,
            require_signature: true,
            require_artifacts_exist: false,
            require_supply_chain: false,
        }
    }
}

impl std::fmt::Debug for PackSuiteOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PackSuiteOptions")
            .field("manifest_override", &self.manifest_override)
            .field("require_flows", &self.require_flows)
            .field(
                "runtime_adapter",
                if self.runtime_adapter.is_some() {
                    &"Some(<runtime adapter>)"
                } else {
                    &"None"
                },
            )
            .field("require_runtime_match", &self.require_runtime_match)
            .field("require_signature", &self.require_signature)
            .field("require_artifacts_exist", &self.require_artifacts_exist)
            .field("require_supply_chain", &self.require_supply_chain)
            .finish()
    }
}

/// Manifest describing a Greentic pack component.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct PackManifest {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub flow_types: Vec<String>,
    #[serde(default)]
    pub runner_version: Option<String>,
    #[serde(default)]
    pub flow_files: Vec<String>,
    #[serde(default)]
    pub components: Vec<String>,
    #[serde(default)]
    pub secrets: Vec<String>,
    #[serde(default)]
    pub sbom: Option<String>,
    #[serde(default)]
    pub attestations: Vec<String>,
    #[serde(default)]
    pub schema_version: Option<String>,
    #[serde(default)]
    pub schema: Option<String>,
    #[serde(default)]
    pub signature: Option<PackSignature>,
    #[serde(default)]
    pub flows: Vec<PackExport>,
}

/// Signature block describing the pack provenance.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PackSignature {
    #[serde(rename = "type")]
    pub kind: String,
    pub public_key: String,
    pub signature: String,
}

/// Basic metadata for a flow exported by the pack.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct PackExport {
    pub id: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub schema: Option<serde_json::Value>,
}

/// Result of verifying a pack component.
#[derive(Debug, Clone)]
pub struct PackReport {
    pub manifest_path: PathBuf,
    pub manifest: PackManifest,
    pub schema_version: PackSchemaVersion,
    pub runtime_flows: Option<Vec<String>>,
    pub warnings: Vec<String>,
}

/// Supported pack schema versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackSchemaVersion {
    V1,
}

/// Error returned when a pack declares an unknown schema version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownPackSchemaVersion {
    pub found: String,
}

impl std::fmt::Display for UnknownPackSchemaVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown pack schema version '{}'", self.found)
    }
}

impl std::error::Error for UnknownPackSchemaVersion {}

/// Attempts to resolve the pack schema version from the manifest.
///
/// If no schema marker is present, v1 is assumed for backward compatibility.
pub fn detect_pack_schema_version(manifest: &PackManifest) -> Result<PackSchemaVersion> {
    let hint = manifest
        .schema_version
        .as_deref()
        .or(manifest.schema.as_deref());

    match hint.map(|raw| raw.trim().to_ascii_lowercase()) {
        None => Ok(PackSchemaVersion::V1),
        Some(ref value) if value == "1" || value == "v1" || value == "pack.v1" => {
            Ok(PackSchemaVersion::V1)
        }
        Some(value) => Err(UnknownPackSchemaVersion { found: value }.into()),
    }
}

/// Primary entrypoint that verifies the pack exports using the default options.
pub fn verify_pack_exports(component_path: &str) -> Result<PackReport> {
    PackSuiteOptions::default().verify_pack_exports(component_path)
}

impl PackSuiteOptions {
    /// Executes the pack export verification with custom options.
    pub fn verify_pack_exports(&self, component_path: impl AsRef<Path>) -> Result<PackReport> {
        let component_path = component_path.as_ref();
        if !component_path.exists() {
            bail!(
                "component path '{}' does not exist",
                component_path.display()
            );
        }

        validate_pack_layout(component_path)?;

        let manifest_path = resolve_pack_manifest(component_path, self)?;
        let manifest_data = fs::read_to_string(&manifest_path)
            .with_context(|| format!("failed to read manifest {}", manifest_path.display()))?;

        let manifest: PackManifest = if manifest_path
            .extension()
            .is_some_and(|ext| ext == "yaml" || ext == "yml")
        {
            serde_yaml::from_str(&manifest_data).with_context(|| {
                format!("manifest {} is not valid YAML", manifest_path.display())
            })?
        } else {
            serde_json::from_str(&manifest_data).with_context(|| {
                format!("manifest {} is not valid JSON", manifest_path.display())
            })?
        };

        let schema_version = detect_pack_schema_version(&manifest)
            .with_context(|| format!("manifest {}", manifest_path.display()))?;

        let manifest_dir = manifest_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));

        let mut warnings = Vec::new();

        validate_manifest(
            &manifest,
            self.require_flows,
            self.require_signature,
            self.require_artifacts_exist,
            self.require_supply_chain,
            &mut warnings,
            &manifest_dir,
        )
        .with_context(|| format!("manifest {}", manifest_path.display()))?;

        let runtime_flows = if let Some(adapter) = &self.runtime_adapter {
            let flows = adapter.list_flows(component_path).with_context(|| {
                format!(
                    "runtime interrogation failed for {}",
                    component_path.display()
                )
            })?;
            if self.require_runtime_match {
                ensure_runtime_matches_manifest(&manifest, &flows)?;
            }
            Some(flows)
        } else {
            None
        };

        Ok(PackReport {
            manifest_path,
            manifest,
            schema_version,
            runtime_flows,
            warnings,
        })
    }

    /// Convenience helper to configure a runtime adapter.
    pub fn with_runtime_adapter<A>(mut self, adapter: A) -> Self
    where
        A: PackRuntimeAdapter + 'static,
    {
        self.runtime_adapter = Some(Arc::new(adapter));
        self
    }

    /// Convenience helper to override the manifest discovery path.
    pub fn with_manifest_override(mut self, manifest: impl Into<PathBuf>) -> Self {
        self.manifest_override = Some(manifest.into());
        self
    }

    /// Allows diverging runtime exports without failing verification.
    pub fn allow_runtime_mismatch(mut self) -> Self {
        self.require_runtime_match = false;
        self
    }

    /// Allows manifests without signatures (useful for local development).
    pub fn allow_unsigned(mut self) -> Self {
        self.require_signature = false;
        self
    }

    /// Require referenced flow/component paths to exist.
    pub fn require_artifacts(mut self) -> Self {
        self.require_artifacts_exist = true;
        self
    }

    /// Require supply-chain metadata such as SBOM/attestations.
    pub fn require_supply_chain(mut self) -> Self {
        self.require_supply_chain = true;
        self
    }
}

/// Attempts to resolve the manifest associated with a component path.
pub fn resolve_pack_manifest(component_path: &Path, options: &PackSuiteOptions) -> Result<PathBuf> {
    if let Some(override_path) = &options.manifest_override {
        if !override_path.exists() {
            bail!(
                "provided manifest override '{}' does not exist",
                override_path.display()
            );
        }
        return Ok(override_path.clone());
    }

    if let Ok(env_override) = std::env::var("GREENTIC_PACK_MANIFEST") {
        let env_path = PathBuf::from(env_override);
        if env_path.exists() {
            return Ok(env_path);
        }
    }

    if component_path.is_file() {
        if component_path
            .extension()
            .is_some_and(|ext| ext == "json" || ext == "yaml" || ext == "yml")
        {
            return Ok(component_path.to_path_buf());
        }
        let mut candidates = Vec::new();
        candidates.push(component_path.with_extension("json"));
        candidates.push(component_path.with_extension("yaml"));
        candidates.push(component_path.with_extension("yml"));

        if let Some(found) = candidates.into_iter().find(|p| p.exists()) {
            return Ok(found);
        }
    }

    let lookup_dir = if component_path.is_file() {
        component_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    } else {
        component_path.to_path_buf()
    };

    let mut candidates = Vec::new();
    for name in [
        "pack.manifest.json",
        "pack.manifest.yaml",
        "pack.manifest.yml",
        "pack.json",
        "pack.yaml",
        "pack.yml",
    ] {
        candidates.push(lookup_dir.join(name));
    }

    if let Some(found) = candidates.into_iter().find(|p| p.exists()) {
        return Ok(found);
    }

    bail!(
        "unable to locate a manifest for '{}' –\
         expected one of pack.manifest.(json|yaml) near the component",
        component_path.display()
    );
}

/// Validates optional pack layout folders if present.
fn validate_pack_layout(component_path: &Path) -> Result<()> {
    for dir in ["flows", "components", "assets", "schemas", "docs"] {
        let path = component_path.join(dir);
        if path.exists() && !path.is_dir() {
            bail!(
                "expected '{}' to be a directory when present (found file {})",
                dir,
                path.display()
            );
        }
    }
    Ok(())
}

fn validate_manifest(
    manifest: &PackManifest,
    require_flows: bool,
    require_signature: bool,
    require_artifacts: bool,
    require_supply_chain: bool,
    warnings: &mut Vec<String>,
    manifest_dir: &Path,
) -> Result<()> {
    let pack_id = manifest
        .id
        .as_deref()
        .or(manifest.name.as_deref())
        .ok_or_else(|| anyhow::anyhow!("pack manifest must declare an id or name"))?;
    if pack_id.trim().is_empty() {
        bail!("pack manifest id/name must not be empty");
    }

    if manifest
        .version
        .as_deref()
        .map(|v| v.trim().is_empty())
        .unwrap_or(true)
    {
        bail!("pack manifest must declare a non-empty version");
    }

    if let Some(kind) = &manifest.kind
        && kind.trim().is_empty()
    {
        bail!("pack manifest kind must not be empty when provided");
    }

    for flow_type in &manifest.flow_types {
        if flow_type.trim().is_empty() {
            bail!("pack manifest flow_types entries must not be empty");
        }
    }

    if let Some(runner_version) = &manifest.runner_version
        && runner_version.trim().is_empty()
    {
        bail!("pack manifest runner_version must not be empty when provided");
    }

    for secret in &manifest.secrets {
        if secret.trim().is_empty() {
            bail!("pack manifest secrets must not contain empty entries");
        }
    }

    if require_signature {
        match manifest.signature.as_ref() {
            Some(sig) => {
                if sig.kind.trim().is_empty()
                    || sig.public_key.trim().is_empty()
                    || sig.signature.trim().is_empty()
                {
                    bail!("pack manifest signature block is incomplete");
                }
            }
            None => bail!("pack manifest missing signature block"),
        }
    }

    if let Some(sbom) = &manifest.sbom {
        if sbom.trim().is_empty() {
            bail!("pack manifest sbom reference must not be empty when provided");
        }
    } else if require_supply_chain {
        bail!("pack manifest missing sbom reference");
    } else {
        warnings.push("pack manifest missing sbom reference".to_string());
    }

    if manifest.attestations.is_empty() {
        if require_supply_chain {
            bail!("pack manifest missing attestation references");
        } else {
            warnings.push("pack manifest missing attestation references".to_string());
        }
    } else {
        for att in &manifest.attestations {
            if att.trim().is_empty() {
                bail!("pack manifest attestations must not contain empty entries");
            }
        }
    }

    if require_flows && manifest.flows.is_empty() {
        bail!("pack must export at least one flow");
    }

    let mut seen_ids = HashSet::new();
    for export in &manifest.flows {
        if export.id.trim().is_empty() {
            bail!("found flow with an empty id");
        }
        if !seen_ids.insert(export.id.clone()) {
            bail!("duplicate flow id '{}'", export.id);
        }
        if let Some(schema) = &export.schema
            && !schema.is_object()
        {
            bail!(
                "flow '{}' schema must be a JSON object when provided",
                export.id
            );
        }

        if require_artifacts && let Some(path) = &export.path {
            ensure_path_exists(manifest_dir, path, "flow")?;
        }
    }

    if require_artifacts {
        for flow_path in &manifest.flow_files {
            ensure_path_exists(manifest_dir, flow_path, "flow")?;
        }

        for component in &manifest.components {
            ensure_path_exists(manifest_dir, component, "component")?;
        }
    }

    Ok(())
}

fn ensure_path_exists(root: &Path, relative: &str, kind: &str) -> Result<()> {
    let path = root.join(relative);
    if !path.exists() {
        bail!(
            "{} path '{}' does not exist (resolved to {})",
            kind,
            relative,
            path.display()
        );
    }
    Ok(())
}

fn ensure_runtime_matches_manifest(
    manifest: &PackManifest,
    runtime_flows: &[String],
) -> Result<()> {
    let manifest_set: HashSet<_> = manifest.flows.iter().map(|flow| flow.id.as_str()).collect();
    let runtime_set: HashSet<_> = runtime_flows.iter().map(|id| id.as_str()).collect();

    let missing_from_runtime: Vec<_> = manifest_set.difference(&runtime_set).cloned().collect();
    let missing_from_manifest: Vec<_> = runtime_set.difference(&manifest_set).cloned().collect();

    if !missing_from_runtime.is_empty() || !missing_from_manifest.is_empty() {
        bail!(
            "runtime exports do not align with manifest\nmissing in runtime: {missing_from_runtime:?}\nmissing in manifest: {missing_from_manifest:?}"
        );
    }

    Ok(())
}
