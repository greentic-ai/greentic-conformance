use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand, ValueEnum};
use greentic_conformance::{
    FlowValidationOptions, PackSuiteOptions, RunnerExpectation, RunnerOptions,
};
use greentic_pack::{PackLoad, SigningPolicy, builder::PackMeta, open_pack};
use serde::Serialize;

#[derive(Parser)]
#[command(
    name = "greentic-conformance",
    version,
    about = "Greentic conformance CLI"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
#[allow(clippy::enum_variant_names)]
enum Commands {
    /// Validate a .gtpack archive against Pack v1 structural rules.
    CheckPack {
        /// Path to the .gtpack archive.
        path: PathBuf,
        /// Allow dev/self-signed packs instead of requiring strict signatures.
        #[arg(long)]
        allow_dev_signatures: bool,
        /// Allow unsigned packs (skips signature verification).
        #[arg(long)]
        allow_unsigned: bool,
        /// Output format (json or text).
        #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
        format: OutputFormat,
    },
    /// Placeholder for flow validation (to be implemented).
    CheckFlow {
        /// Path to a folder containing flow definitions.
        path: PathBuf,
        /// Allow flows without an inline schema block.
        #[arg(long)]
        allow_missing_schema: bool,
        /// Output format (json or text).
        #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
        format: OutputFormat,
    },
    /// Placeholder for component validation (to be implemented).
    CheckComponent {
        /// Path to a component binary.
        path: PathBuf,
        /// Optional runtime flow list (JSON array of strings) to compare against the manifest.
        #[arg(long)]
        runtime_flows: Option<String>,
        /// Override the manifest path instead of auto-discovering it.
        #[arg(long)]
        manifest: Option<PathBuf>,
        /// Allow runtime exports to diverge from the manifest when runtime flows are supplied.
        #[arg(long)]
        allow_runtime_mismatch: bool,
        /// Allow unsigned manifests (skip signature requirement).
        #[arg(long)]
        allow_unsigned: bool,
        /// Output format (json or text).
        #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
        format: OutputFormat,
    },
    /// Placeholder for runner validation (to be implemented).
    CheckRunner {
        /// Path to a runner binary.
        path: PathBuf,
        /// Pack path to use for the smoke test (falls back to GREENTIC_PACK_PATH).
        #[arg(long)]
        pack: Option<PathBuf>,
        /// Treat non-zero exit as acceptable.
        #[arg(long)]
        allow_failure: bool,
        /// Require stdout to be valid JSON.
        #[arg(long)]
        require_json_stdout: bool,
        /// Expected JSON fragment that must be contained in stdout.
        #[arg(long)]
        expected_egress: Option<String>,
        /// Output format (json or text).
        #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
        format: OutputFormat,
    },
    /// Placeholder for deployer validation (to be implemented).
    CheckDeployer {
        /// Path to a deployer binary.
        path: PathBuf,
        /// Output format (json or text).
        #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
        format: OutputFormat,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum OutputFormat {
    Json,
    Text,
}

#[derive(Debug, Serialize)]
struct FlowCheckReport {
    root: String,
    flow_count: usize,
    flow_v1_basic: bool,
    flow_v1_safe: bool,
    issues: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ComponentCheckReport {
    component: String,
    component_v1_wit_only: bool,
    component_v1_hosted: bool,
    issues: Vec<String>,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct RunnerCheckReport {
    runner: String,
    runner_v1: bool,
    issues: Vec<String>,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DeployerCheckReport {
    deployer: String,
    deployer_v1: bool,
    issues: Vec<String>,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct PackCheckReport {
    pack_path: String,
    signature_policy: String,
    pack_v1_basic: bool,
    pack_v1_full: bool,
    signature_ok: bool,
    sbom_ok: bool,
    issues: Vec<String>,
    warnings: Vec<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::CheckPack {
            path,
            allow_dev_signatures,
            allow_unsigned,
            format,
        } => {
            let report = check_pack(&path, allow_dev_signatures, allow_unsigned)
                .with_context(|| format!("failed to check pack {}", path.display()))?;
            emit_pack_report(report, format)?;
        }
        Commands::CheckFlow {
            path,
            allow_missing_schema,
            format,
        } => {
            let report = check_flow(&path, allow_missing_schema)
                .with_context(|| format!("failed to check flows at {}", path.display()))?;
            emit_flow_report(report, format)?;
        }
        Commands::CheckComponent {
            path,
            runtime_flows,
            manifest,
            allow_runtime_mismatch,
            allow_unsigned,
            format,
        } => {
            let report = check_component(
                &path,
                runtime_flows.as_deref(),
                manifest.as_deref(),
                allow_runtime_mismatch,
                allow_unsigned,
            )?;
            emit_component_report(report, format)?;
        }
        Commands::CheckRunner {
            path,
            pack,
            allow_failure,
            require_json_stdout,
            expected_egress,
            format,
        } => {
            let report = check_runner(
                &path,
                pack.as_deref(),
                allow_failure,
                require_json_stdout,
                expected_egress.as_deref(),
            )?;
            emit_runner_report(report, format)?;
        }
        Commands::CheckDeployer { path, format } => {
            let report = check_deployer(&path)?;
            emit_deployer_report(report, format)?;
        }
    }

    Ok(())
}

fn emit_pack_report(report: PackCheckReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        OutputFormat::Text => {
            println!("Pack: {}", report.pack_path);
            println!("Signature policy: {}", report.signature_policy);
            println!("pack_v1_basic: {}", report.pack_v1_basic);
            println!("pack_v1_full: {}", report.pack_v1_full);
            if !report.issues.is_empty() {
                println!("Issues:");
                for issue in &report.issues {
                    println!("- {issue}");
                }
            }
            if !report.warnings.is_empty() {
                println!("Warnings:");
                for warn in &report.warnings {
                    println!("- {warn}");
                }
            }
        }
    }
    Ok(())
}

fn emit_flow_report(report: FlowCheckReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        OutputFormat::Text => {
            println!("Flow root: {}", report.root);
            println!("flow_v1_basic: {}", report.flow_v1_basic);
            println!("flow_v1_safe: {}", report.flow_v1_safe);
            println!("flows discovered: {}", report.flow_count);
            if !report.issues.is_empty() {
                println!("Issues:");
                for issue in &report.issues {
                    println!("- {issue}");
                }
            }
        }
    }
    Ok(())
}

fn emit_component_report(report: ComponentCheckReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        OutputFormat::Text => {
            println!("Component: {}", report.component);
            println!("component_v1_wit_only: {}", report.component_v1_wit_only);
            println!("component_v1_hosted: {}", report.component_v1_hosted);
            if !report.issues.is_empty() {
                println!("Issues:");
                for issue in &report.issues {
                    println!("- {issue}");
                }
            }
            if !report.warnings.is_empty() {
                println!("Warnings:");
                for warn in &report.warnings {
                    println!("- {warn}");
                }
            }
        }
    }
    Ok(())
}

fn emit_runner_report(report: RunnerCheckReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        OutputFormat::Text => {
            println!("Runner: {}", report.runner);
            println!("runner_v1: {}", report.runner_v1);
            if !report.issues.is_empty() {
                println!("Issues:");
                for issue in &report.issues {
                    println!("- {issue}");
                }
            }
            if !report.warnings.is_empty() {
                println!("Warnings:");
                for warn in &report.warnings {
                    println!("- {warn}");
                }
            }
        }
    }
    Ok(())
}

fn emit_deployer_report(report: DeployerCheckReport, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        OutputFormat::Text => {
            println!("Deployer: {}", report.deployer);
            println!("deployer_v1: {}", report.deployer_v1);
            if !report.issues.is_empty() {
                println!("Issues:");
                for issue in &report.issues {
                    println!("- {issue}");
                }
            }
            if !report.warnings.is_empty() {
                println!("Warnings:");
                for warn in &report.warnings {
                    println!("- {warn}");
                }
            }
        }
    }
    Ok(())
}

fn check_pack(
    path: &Path,
    allow_dev_signatures: bool,
    allow_unsigned: bool,
) -> Result<PackCheckReport> {
    let policy = if allow_unsigned || allow_dev_signatures {
        SigningPolicy::DevOk
    } else {
        SigningPolicy::Strict
    };

    let pack = open_pack(path, policy)
        .map_err(|err| anyhow!("pack failed verification: {}", err.message))?;

    let mut issues = Vec::new();
    let mut warnings = pack.report.warnings.clone();
    perform_structural_checks(&pack, &mut issues, &mut warnings, allow_unsigned);

    let pack_v1_basic = issues.is_empty();
    let pack_v1_full =
        pack_v1_basic && warnings.is_empty() && pack.report.signature_ok && pack.report.sbom_ok;

    Ok(PackCheckReport {
        pack_path: path.display().to_string(),
        signature_policy: if allow_unsigned {
            "unsigned_ok".to_string()
        } else {
            match policy {
                SigningPolicy::DevOk => "dev_ok".to_string(),
                SigningPolicy::Strict => "strict".to_string(),
            }
        },
        pack_v1_basic,
        pack_v1_full,
        signature_ok: if allow_unsigned {
            true
        } else {
            pack.report.signature_ok
        },
        sbom_ok: pack.report.sbom_ok,
        issues,
        warnings,
    })
}

fn check_flow(path: &Path, allow_missing_schema: bool) -> Result<FlowCheckReport> {
    let mut options = FlowValidationOptions::default();
    if allow_missing_schema {
        options = options.allow_missing_schema();
    }
    let require_schema = options.require_schema;

    match options.validate_flow_folder(path) {
        Ok(report) => Ok(FlowCheckReport {
            root: report.root.display().to_string(),
            flow_count: report.flows.len(),
            flow_v1_basic: true,
            flow_v1_safe: require_schema,
            issues: Vec::new(),
        }),
        Err(err) => Ok(FlowCheckReport {
            root: path.display().to_string(),
            flow_count: 0,
            flow_v1_basic: false,
            flow_v1_safe: false,
            issues: vec![err.to_string()],
        }),
    }
}

fn check_component(
    path: &Path,
    runtime_flows: Option<&str>,
    manifest: Option<&Path>,
    allow_runtime_mismatch: bool,
    allow_unsigned: bool,
) -> Result<ComponentCheckReport> {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();

    let metadata = fs::metadata(path)
        .with_context(|| format!("component path '{}' not readable", path.display()))?;
    if !metadata.is_file() {
        issues.push("component path is not a file".to_string());
    }
    if metadata.len() == 0 {
        issues.push("component file is empty".to_string());
    }
    if !is_executable(&metadata, path) {
        warnings.push("component file is not marked executable".to_string());
    }

    let mut component_v1_wit_only = issues.is_empty();
    let mut component_v1_hosted = issues.is_empty();
    if issues.is_empty() {
        let adapter = runtime_flows
            .map(|raw| -> Result<_> {
                let parsed: Vec<String> = serde_json::from_str(raw).with_context(|| {
                    "runtime flows must be a JSON array of strings (e.g. [\"flow.a\", \"flow.b\"])"
                })?;
                Ok(parsed)
            })
            .transpose()?;

        let mut options = PackSuiteOptions::default();
        if let Some(manifest_override) = manifest {
            options = options.with_manifest_override(manifest_override);
        }
        if allow_runtime_mismatch {
            options = options.allow_runtime_mismatch();
        }
        if allow_unsigned {
            options = options.allow_unsigned();
        }

        if let Some(runtime_flows) = adapter {
            let adapter = move |_component: &Path| Ok(runtime_flows.clone());
            let options = options.clone().with_runtime_adapter(adapter);
            match options.verify_pack_exports(path.to_string_lossy().as_ref()) {
                Ok(report) => {
                    component_v1_wit_only = true;
                    component_v1_hosted = report.runtime_flows.is_some() || component_v1_hosted;
                }
                Err(err) => {
                    component_v1_wit_only = false;
                    component_v1_hosted = false;
                    issues.push(format!("pack export verification failed: {err}"));
                }
            }
        } else {
            match options.verify_pack_exports(path.to_string_lossy().as_ref()) {
                Ok(report) => {
                    component_v1_wit_only = true;
                    component_v1_hosted = report.runtime_flows.is_some() || component_v1_hosted;
                }
                Err(err) => {
                    component_v1_wit_only = false;
                    component_v1_hosted = false;
                    issues.push(format!("pack export verification failed: {err}"));
                }
            }
        }

        if component_v1_hosted && !component_v1_wit_only {
            component_v1_hosted = false;
        }
    }

    Ok(ComponentCheckReport {
        component: path.display().to_string(),
        component_v1_wit_only,
        component_v1_hosted,
        issues,
        warnings,
    })
}

fn check_runner(
    path: &Path,
    pack_path: Option<&Path>,
    allow_failure: bool,
    require_json_stdout: bool,
    expected_egress: Option<&str>,
) -> Result<RunnerCheckReport> {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();

    let metadata = fs::metadata(path)
        .with_context(|| format!("runner path '{}' not readable", path.display()))?;
    if !metadata.is_file() {
        issues.push("runner path is not a file".to_string());
    }
    if metadata.len() == 0 {
        issues.push("runner file is empty".to_string());
    }
    if !is_executable(&metadata, path) {
        warnings.push("runner file is not marked executable".to_string());
    }

    let mut runner_v1 = issues.is_empty();

    let pack_path = pack_path
        .map(PathBuf::from)
        .or_else(|| std::env::var("GREENTIC_PACK_PATH").ok().map(PathBuf::from));

    if let Some(pack_path) = pack_path {
        if !pack_path.exists() {
            issues.push(format!(
                "provided pack path '{}' does not exist",
                pack_path.display()
            ));
        }
        if issues.is_empty() {
            let mut expectation = RunnerExpectation::default();
            if allow_failure {
                expectation = expectation.allow_failure();
            }
            if require_json_stdout {
                expectation = expectation.require_json_stdout();
            }
            if let Some(raw) = expected_egress {
                let parsed: serde_json::Value = serde_json::from_str(raw)
                    .with_context(|| "expected egress must be valid JSON (object/array/value)")?;
                expectation = expectation.with_expected_egress(parsed);
            }

            let options = RunnerOptions::default().with_expectation(expectation);
            match options.smoke_run_with_mocks(path, &pack_path) {
                Ok(_) => runner_v1 = true,
                Err(err) => {
                    runner_v1 = false;
                    issues.push(format!("runner smoke test failed: {err}"));
                }
            }
        }
    } else {
        warnings.push(
            "no pack path provided; skipped runner smoke test with mock connectors".to_string(),
        );
    }

    if !issues.is_empty() {
        runner_v1 = false;
    }

    Ok(RunnerCheckReport {
        runner: path.display().to_string(),
        runner_v1,
        issues,
        warnings,
    })
}

fn check_deployer(path: &Path) -> Result<DeployerCheckReport> {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();

    let metadata = fs::metadata(path)
        .with_context(|| format!("deployer path '{}' not readable", path.display()))?;
    if !metadata.is_file() {
        issues.push("deployer path is not a file".to_string());
    }
    if metadata.len() == 0 {
        issues.push("deployer file is empty".to_string());
    }
    if !is_executable(&metadata, path) {
        warnings.push("deployer file is not marked executable".to_string());
    }

    // Best-effort sanity check: ensure the binary responds to --help without crashing.
    if issues.is_empty() {
        let output = std::process::Command::new(path)
            .arg("--help")
            .output()
            .with_context(|| {
                format!("failed to invoke deployer '{}' with --help", path.display())
            })?;
        if !output.status.success() {
            issues.push(format!(
                "deployer '{}' --help exited with status {}",
                path.display(),
                output.status.code().unwrap_or_default()
            ));
        }
    }

    Ok(DeployerCheckReport {
        deployer: path.display().to_string(),
        deployer_v1: issues.is_empty(),
        issues,
        warnings,
    })
}

fn is_executable(metadata: &fs::Metadata, path: &Path) -> bool {
    #[cfg(unix)]
    {
        let _ = path;
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        mode & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        // On non-Unix, fall back to extension heuristics.
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("exe") || ext.eq_ignore_ascii_case("bat"))
            .unwrap_or(false)
    }
}

fn perform_structural_checks(
    pack: &PackLoad,
    issues: &mut Vec<String>,
    warnings: &mut Vec<String>,
    allow_unsigned: bool,
) {
    validate_meta(&pack.manifest.meta, issues);

    let sbom_paths: HashSet<&str> = pack.sbom.iter().map(|f| f.path.as_str()).collect();
    let mut flow_ids = HashSet::new();
    for flow in &pack.manifest.flows {
        if !flow_ids.insert(flow.id.clone()) {
            issues.push(format!("duplicate flow id `{}`", flow.id));
        }

        check_file_present("flow.entry", &flow.entry, &sbom_paths, issues);
        check_file_present("flow.file_yaml", &flow.file_yaml, &sbom_paths, issues);
        check_file_present("flow.file_json", &flow.file_json, &sbom_paths, issues);
    }

    for entry in &pack.manifest.meta.entry_flows {
        if !flow_ids.contains(entry) {
            issues.push(format!(
                "meta.entry_flows references missing flow `{entry}`"
            ));
        }
    }

    let mut component_keys = HashMap::new();
    for component in &pack.manifest.components {
        let key = format!("{}@{}", component.name, component.version);
        if let Some(prev) = component_keys.insert(key.clone(), component) {
            issues.push(format!(
                "duplicate component entry `{}` at files {:?} and {:?}",
                key, prev.file_wasm, component.file_wasm
            ));
        }

        check_file_present("component.wasm", &component.file_wasm, &sbom_paths, issues);
        if let Some(schema) = &component.schema_file {
            check_file_present("component.schema", schema, &sbom_paths, issues);
        }
        if let Some(manifest) = &component.manifest_file {
            check_file_present("component.manifest", manifest, &sbom_paths, issues);
        }
    }

    if !pack.report.signature_ok {
        if allow_unsigned {
            warnings.push(
                "pack signature verification failed (allowed by --allow-unsigned)".to_string(),
            );
        } else {
            issues.push("pack signature verification failed".to_string());
        }
    }
    if !pack.report.sbom_ok {
        warnings.push("sbom validation reported issues".to_string());
    }
}

fn validate_meta(meta: &PackMeta, issues: &mut Vec<String>) {
    if meta.pack_id.trim().is_empty() {
        issues.push("meta.pack_id is required".to_string());
    }
    if meta.name.trim().is_empty() {
        issues.push("meta.name is required".to_string());
    }
    if meta.entry_flows.is_empty() {
        issues.push("meta.entry_flows must include at least one entry".to_string());
    }
    if meta.created_at_utc.trim().is_empty() {
        issues.push("meta.created_at_utc is required".to_string());
    }
}

fn check_file_present(
    kind: &str,
    path: &str,
    sbom_paths: &HashSet<&str>,
    issues: &mut Vec<String>,
) {
    if path.trim().is_empty() {
        issues.push(format!("{kind} path is empty"));
        return;
    }

    if !sbom_paths.contains(path) {
        issues.push(format!("{kind} `{path}` missing from sbom.json"));
    }
}
