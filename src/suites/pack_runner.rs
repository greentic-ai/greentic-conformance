use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde_json::Value;

use crate::{
    PackReport, PackSuiteOptions, RunnerOptions, RunnerReport, assertions,
    env::{self, TenantContext},
};

/// Configuration for running the pack + runner conformance suite.
#[derive(Debug, Clone)]
pub struct PackRunnerSuiteConfig {
    pub component_path: PathBuf,
    pub manifest_override: Option<PathBuf>,
    pub require_signature: bool,
    pub pack_options: PackSuiteOptions,
    pub runner: Option<RunnerHarnessConfig>,
}

impl PackRunnerSuiteConfig {
    /// Creates a new configuration targeting the provided component path.
    pub fn new(component_path: impl Into<PathBuf>) -> Self {
        Self {
            component_path: component_path.into(),
            manifest_override: None,
            require_signature: true,
            pack_options: PackSuiteOptions::default(),
            runner: None,
        }
    }

    /// Builds a configuration from the canonical Greentic environment variables.
    ///
    /// Required:
    /// - `GREENTIC_PACK_PATH`
    ///
    /// Optional:
    /// - `GREENTIC_PACK_MANIFEST`
    /// - `GREENTIC_RUNNER_BIN`
    /// - `ALLOW_UNSIGNED` (skip signature checks when set)
    pub fn from_env() -> Result<Self> {
        let component_path = PathBuf::from(env::required_env("GREENTIC_PACK_PATH")?);
        let manifest_override = std::env::var("GREENTIC_PACK_MANIFEST")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from);
        let runner_binary = std::env::var("GREENTIC_RUNNER_BIN")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from);

        let mut config = Self::new(component_path);
        if let Some(manifest) = manifest_override {
            config = config.with_manifest_override(manifest);
        }
        if let Some(binary) = runner_binary {
            config = config.with_runner_binary(binary);
        }
        if env::bool_flag("ALLOW_UNSIGNED") {
            config = config.allow_unsigned();
        }
        Ok(config)
    }

    /// Overrides the manifest path that should be used for validation.
    pub fn with_manifest_override(mut self, manifest: impl Into<PathBuf>) -> Self {
        self.manifest_override = Some(manifest.into());
        self
    }

    /// Replaces the pack suite options (for example to inject a runtime adapter).
    pub fn with_pack_options(mut self, options: PackSuiteOptions) -> Self {
        self.pack_options = options;
        self
    }

    /// Skips manifest signature enforcement.
    pub fn allow_unsigned(mut self) -> Self {
        self.require_signature = false;
        self.pack_options.require_signature = false;
        self
    }

    /// Registers a runner harness configuration.
    pub fn with_runner(mut self, runner: RunnerHarnessConfig) -> Self {
        self.runner = Some(runner);
        self
    }

    /// Registers a runner binary using default options.
    pub fn with_runner_binary(self, binary: impl Into<PathBuf>) -> Self {
        self.with_runner(RunnerHarnessConfig::new(binary))
    }
}

/// Configuration describing how to execute the runner smoke test.
#[derive(Debug, Clone)]
pub struct RunnerHarnessConfig {
    pub binary: PathBuf,
    pub options: RunnerOptions,
}

impl RunnerHarnessConfig {
    /// Creates a runner harness using the default smoke test options.
    pub fn new(binary: impl Into<PathBuf>) -> Self {
        Self {
            binary: binary.into(),
            options: RunnerOptions::default(),
        }
    }

    /// Overrides the runner options (for example to inject extra args or expectations).
    pub fn with_options(mut self, options: RunnerOptions) -> Self {
        self.options = options;
        self
    }
}

/// Report returned after executing the pack/runner suite.
#[derive(Debug, Clone)]
pub struct PackRunnerSuiteReport {
    pub tenant: TenantContext,
    pub component_path: PathBuf,
    pub pack_report: PackReport,
    pub runner_report: Option<RunnerReport>,
}

/// Runs the pack/runner suite using the provided configuration.
pub fn run_suite(config: PackRunnerSuiteConfig) -> Result<PackRunnerSuiteReport> {
    let tenant = TenantContext::detect()?;
    let PackRunnerSuiteConfig {
        component_path,
        manifest_override,
        require_signature,
        pack_options,
        runner,
    } = config;

    if !component_path.exists() {
        bail!(
            "component path '{}' does not exist",
            component_path.display()
        );
    }

    let options = if let Some(manifest_path) = manifest_override {
        pack_options.with_manifest_override(manifest_path)
    } else {
        pack_options
    };

    let pack_report = options
        .verify_pack_exports(&component_path)
        .with_context(|| {
            format!(
                "failed to verify pack exports for '{}'",
                component_path.display()
            )
        })?;

    if !pack_report.warnings.is_empty() {
        tracing::warn!(
            warnings = ?pack_report.warnings,
            "pack verification emitted warnings"
        );
    }

    if require_signature {
        let manifest_value: Value = serde_json::to_value(&pack_report.manifest)?;
        assertions::assert_signed_pack(&manifest_value)?;
    }

    let runner_report = if let Some(runner) = runner {
        if !runner.binary.exists() {
            bail!("runner binary '{}' does not exist", runner.binary.display());
        }
        let report = runner
            .options
            .clone()
            .smoke_run_with_mocks(&runner.binary, &component_path)
            .with_context(|| {
                format!(
                    "runner smoke test failed using '{}' and pack '{}'",
                    runner.binary.display(),
                    component_path.display()
                )
            })?;
        Some(report)
    } else {
        None
    };

    Ok(PackRunnerSuiteReport {
        tenant,
        component_path,
        pack_report,
        runner_report,
    })
}
