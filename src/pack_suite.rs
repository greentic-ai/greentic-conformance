use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

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
}

impl Default for PackSuiteOptions {
    fn default() -> Self {
        Self {
            manifest_override: None,
            require_flows: true,
            runtime_adapter: None,
            require_runtime_match: true,
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
            .finish()
    }
}

/// Manifest describing a Greentic pack component.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PackManifest {
    pub signature: String,
    #[serde(default)]
    pub flows: Vec<PackExport>,
}

/// Basic metadata for a flow exported by the pack.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PackExport {
    pub id: String,
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
    pub runtime_flows: Option<Vec<String>>,
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

        validate_manifest(&manifest, self.require_flows)
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
            runtime_flows,
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

fn validate_manifest(manifest: &PackManifest, require_flows: bool) -> Result<()> {
    if manifest.signature.trim().is_empty() {
        bail!("pack signature must be a non-empty string");
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
        if let Some(schema) = &export.schema {
            if !schema.is_object() {
                bail!(
                    "flow '{}' schema must be a JSON object when provided",
                    export.id
                );
            }
        }
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
            "runtime exports do not align with manifest\nmissing in runtime: {:?}\nmissing in manifest: {:?}",
            missing_from_runtime,
            missing_from_manifest
        );
    }

    Ok(())
}
