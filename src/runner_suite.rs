use std::{
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{bail, Context, Result};
use serde_json::Value;

/// Runtime options controlling how the runner is exercised.
#[derive(Debug, Clone)]
pub struct RunnerOptions {
    /// Additional arguments passed to the runner after the pack path.
    pub args: Vec<String>,
    /// Additional environment variables set for the runner invocation.
    pub env: Vec<(String, String)>,
    /// Optional working directory for the runner.
    pub working_dir: Option<PathBuf>,
    /// Optional stdin payload forwarded to the runner.
    pub stdin: Option<String>,
    /// Expectations that should be asserted on the runner output.
    pub expectation: Option<RunnerExpectation>,
}

impl Default for RunnerOptions {
    fn default() -> Self {
        Self {
            args: Vec::new(),
            env: Vec::new(),
            working_dir: None,
            stdin: None,
            expectation: Some(RunnerExpectation::default()),
        }
    }
}

impl RunnerOptions {
    /// Adds a CLI argument that will be appended after the pack path.
    pub fn add_arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Adds an environment variable that will be set for the runner process.
    pub fn add_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Specifies the working directory used when spawning the runner.
    pub fn with_working_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.working_dir = Some(path.into());
        self
    }

    /// Provides an optional stdin payload that will be written to the process.
    pub fn with_stdin(mut self, payload: impl Into<String>) -> Self {
        self.stdin = Some(payload.into());
        self
    }

    /// Overrides the expectation used when validating the runner outputs.
    pub fn with_expectation(mut self, expectation: RunnerExpectation) -> Self {
        self.expectation = Some(expectation);
        self
    }

    /// Disables all expectations; the harness will only capture outputs.
    pub fn disable_expectation(mut self) -> Self {
        self.expectation = None;
        self
    }
}

/// Defines the behaviour we expect from the runner invocation.
#[derive(Debug, Clone)]
pub struct RunnerExpectation {
    pub expect_success: bool,
    pub expected_egress: Option<Value>,
    pub stdout_must_be_json: bool,
}

impl Default for RunnerExpectation {
    fn default() -> Self {
        Self {
            expect_success: true,
            expected_egress: None,
            stdout_must_be_json: false,
        }
    }
}

impl RunnerExpectation {
    /// Create an expectation that simply checks for process success.
    pub fn success() -> Self {
        Self::default()
    }

    /// Require that stdout is valid JSON.
    pub fn require_json_stdout(mut self) -> Self {
        self.stdout_must_be_json = true;
        self
    }

    /// Provide an expected JSON fragment that must be contained in stdout.
    pub fn with_expected_egress(mut self, value: Value) -> Self {
        self.expected_egress = Some(value);
        self
    }

    /// Allow the runner to exit with a non-zero status.
    pub fn allow_failure(mut self) -> Self {
        self.expect_success = false;
        self
    }
}

/// Snapshot of a single runner invocation.
#[derive(Debug, Clone)]
pub struct RunnerSnapshot {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
    pub stdout_json: Option<Value>,
}

/// Report returned after running the smoke test.
#[derive(Debug, Clone)]
pub struct RunnerReport {
    pub binary: PathBuf,
    pub pack_path: PathBuf,
    pub snapshot: RunnerSnapshot,
}

/// Smoke test a runner binary with mock connectors and a pack path.
pub fn smoke_run_with_mocks(host_bin: &str, pack_path: &str) -> Result<RunnerReport> {
    RunnerOptions::default().smoke_run_with_mocks(host_bin, pack_path)
}

impl RunnerOptions {
    /// Smoke test helper using the provided options.
    pub fn smoke_run_with_mocks(
        self,
        host_bin: impl AsRef<Path>,
        pack_path: impl AsRef<Path>,
    ) -> Result<RunnerReport> {
        let host_bin = host_bin.as_ref();
        let pack_path = pack_path.as_ref();

        if !host_bin.exists() {
            bail!("runner binary '{}' does not exist", host_bin.display());
        }
        if !pack_path.exists() {
            bail!("pack path '{}' does not exist", pack_path.display());
        }

        let mut command = Command::new(host_bin);
        command.arg(pack_path);
        for arg in &self.args {
            command.arg(arg);
        }
        command.env("GREENTIC_CONFORMANCE", "1");
        command.env("GREENTIC_CONFORMANCE_MODE", "mock");
        command.env("GREENTIC_PACK_PATH", pack_path);

        let online_enabled = std::env::var("GREENTIC_ENABLE_ONLINE")
            .map(|val| val == "1" || val.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if !online_enabled {
            command.env("GREENTIC_DISABLE_NETWORK", "1");
        }

        for (key, value) in &self.env {
            command.env(key, value);
        }

        if let Some(dir) = &self.working_dir {
            command.current_dir(dir);
        }

        if let Some(stdin_payload) = &self.stdin {
            use std::io::Write;
            let mut child = command
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .with_context(|| {
                    format!(
                        "failed to spawn runner '{}' in directory '{}'",
                        host_bin.display(),
                        self.working_dir
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|| std::env::current_dir()
                                .map(|cwd| cwd.display().to_string())
                                .unwrap_or_else(|_| "<unknown>".into()))
                    )
                })?;
            if let Some(stdin) = &mut child.stdin {
                stdin
                    .write_all(stdin_payload.as_bytes())
                    .context("failed to write stdin payload to runner")?;
            }
            let output = child
                .wait_with_output()
                .context("failed to wait for runner")?;
            return self.handle_output(host_bin, pack_path, output);
        }

        let output = command
            .output()
            .with_context(|| format!("failed to invoke runner '{}'", host_bin.display()))?;

        self.handle_output(host_bin, pack_path, output)
    }

    fn handle_output(
        self,
        host_bin: &Path,
        pack_path: &Path,
        output: std::process::Output,
    ) -> Result<RunnerReport> {
        let exit_code = output.status.code().unwrap_or_default();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        let mut stdout_json = None;
        if let Some(expectation) = &self.expectation {
            if expectation.expect_success && !output.status.success() {
                bail!(
                    "runner '{}' exited with non-zero status {}. stderr:\n{}",
                    host_bin.display(),
                    exit_code,
                    stderr
                );
            }

            if expectation.stdout_must_be_json || expectation.expected_egress.is_some() {
                let parsed: Value = serde_json::from_str(stdout.trim()).with_context(|| {
                    format!(
                        "runner '{}' stdout is not valid JSON:\n{}",
                        host_bin.display(),
                        stdout
                    )
                })?;
                if let Some(expected) = &expectation.expected_egress {
                    if !json_contains(&parsed, expected) {
                        bail!(
                            "runner '{}' stdout does not contain expected egress\nexpected: {}\nactual: {}",
                            host_bin.display(),
                            expected,
                            parsed
                        );
                    }
                }
                stdout_json = Some(parsed);
            }
        }

        let snapshot = RunnerSnapshot {
            status: exit_code,
            stdout,
            stderr,
            stdout_json,
        };

        Ok(RunnerReport {
            binary: host_bin.to_path_buf(),
            pack_path: pack_path.to_path_buf(),
            snapshot,
        })
    }
}

fn json_contains(actual: &Value, expected: &Value) -> bool {
    match (actual, expected) {
        (Value::Object(actual), Value::Object(expected)) => expected.iter().all(|(key, value)| {
            actual
                .get(key)
                .map(|actual_value| json_contains(actual_value, value))
                .unwrap_or(false)
        }),
        (Value::Array(actual), Value::Array(expected)) => expected.iter().all(|expected_item| {
            actual
                .iter()
                .any(|actual_item| json_contains(actual_item, expected_item))
        }),
        _ => actual == expected,
    }
}
