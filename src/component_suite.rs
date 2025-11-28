use std::{
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail};
use serde_json::Value;

/// Worlds that are not allowed in generic Greentic components.
const DENYLISTED_WORLDS: &[&str] = &["greentic:repo-ui-actions/repo-ui-worker@1.0.0"];

/// Options that tune how a component invocation is performed.
#[derive(Debug, Clone)]
pub struct ComponentInvocationOptions {
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub working_dir: Option<PathBuf>,
    pub expect_json_output: bool,
}

impl Default for ComponentInvocationOptions {
    fn default() -> Self {
        Self {
            args: Vec::new(),
            env: Vec::new(),
            working_dir: None,
            expect_json_output: true,
        }
    }
}

impl ComponentInvocationOptions {
    /// Appends a pass-through argument for the component invocation.
    pub fn add_arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Adds an environment variable to the invocation context.
    pub fn add_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Sets the working directory that will be used when spawning the component.
    pub fn with_working_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.working_dir = Some(dir.into());
        self
    }

    /// Turns off the JSON stdout assertion.
    pub fn allow_non_json_output(mut self) -> Self {
        self.expect_json_output = false;
        self
    }
}

/// Result produced after invoking a component.
#[derive(Debug, Clone)]
pub struct ComponentInvocation {
    pub component: PathBuf,
    pub operation: String,
    pub stdout: String,
    pub stderr: String,
    pub status: i32,
    pub output_json: Option<Value>,
}

/// Validates that exported worlds do not include repo/domain-specific entries.
pub fn assert_allowed_worlds(worlds: &[String]) -> Result<()> {
    for world in worlds {
        if DENYLISTED_WORLDS.iter().any(|blocked| world == blocked) {
            bail!("component exports forbidden world '{}'", world);
        }
    }
    Ok(())
}

/// Light validation for legacy tool specs or MCP exec metadata.
pub fn assert_valid_tool_invocation(tool_name: &str, action: &str, payload: &Value) -> Result<()> {
    if tool_name.trim().is_empty() {
        bail!("tool name must not be empty");
    }
    if action.trim().is_empty() {
        bail!("tool action must not be empty");
    }
    if !payload.is_object() {
        bail!("tool payload must be a JSON object");
    }
    Ok(())
}

/// Invokes a generic component using the default options.
pub fn invoke_generic_component(
    component_path: &str,
    op: &str,
    input_json: &str,
) -> Result<ComponentInvocation> {
    ComponentInvocationOptions::default().invoke_generic_component(component_path, op, input_json)
}

impl ComponentInvocationOptions {
    pub fn invoke_generic_component(
        self,
        component_path: impl AsRef<Path>,
        op: &str,
        input_json: &str,
    ) -> Result<ComponentInvocation> {
        let component_path = component_path.as_ref();
        if !component_path.exists() {
            bail!(
                "component binary '{}' does not exist",
                component_path.display()
            );
        }

        // Ensure the input payload is valid JSON up-front so that a harness failure
        // is reported clearly.
        let parsed_input: Value = serde_json::from_str(input_json).with_context(|| {
            format!("component input payload is not valid JSON for operation '{op}'")
        })?;

        let mut command = Command::new(component_path);
        command.arg(op);
        for extra_arg in &self.args {
            command.arg(extra_arg);
        }

        command.env("GREENTIC_COMPONENT_OPERATION", op);
        command.env("GREENTIC_CONFORMANCE", "1");

        for (key, value) in &self.env {
            command.env(key, value);
        }

        if let Some(dir) = &self.working_dir {
            command.current_dir(dir);
        }

        let mut child = command
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .with_context(|| {
                format!(
                    "failed to spawn component '{}' for operation '{}'",
                    component_path.display(),
                    op
                )
            })?;

        if let Some(stdin) = &mut child.stdin {
            use std::io::Write;
            stdin
                .write_all(parsed_input.to_string().as_bytes())
                .context("failed to write component stdin payload")?;
        }

        let output = child.wait_with_output().with_context(|| {
            format!("component '{}' invocation failed", component_path.display())
        })?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let status = output.status.code().unwrap_or_default();

        if !output.status.success() {
            bail!(
                "component '{}' operation '{}' failed with status {}.\nstdout:\n{}\nstderr:\n{}",
                component_path.display(),
                op,
                status,
                stdout,
                stderr
            );
        }

        let output_json = if self.expect_json_output {
            Some(serde_json::from_str(stdout.trim()).with_context(|| {
                format!(
                    "component '{}' stdout is not valid JSON for operation '{}'",
                    component_path.display(),
                    op
                )
            })?)
        } else {
            None
        };

        Ok(ComponentInvocation {
            component: component_path.to_path_buf(),
            operation: op.to_string(),
            stdout,
            stderr,
            status,
            output_json,
        })
    }
}
