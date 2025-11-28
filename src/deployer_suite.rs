use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Command;

/// Validates that applying the deployer twice is idempotent by comparing outputs.
pub fn assert_deployer_idempotent(
    deployer: &Path,
    config: &Path,
    extra_args: &[&str],
) -> Result<()> {
    if !deployer.exists() {
        bail!("deployer binary '{}' does not exist", deployer.display());
    }
    if !config.exists() {
        bail!("deployer config '{}' does not exist", config.display());
    }

    let first =
        run_deployer(deployer, config, extra_args).context("first deployer apply failed")?;
    let second =
        run_deployer(deployer, config, extra_args).context("second deployer apply failed")?;

    if first != second {
        bail!("deployer is not idempotent: outputs differ between runs");
    }
    Ok(())
}

fn run_deployer(deployer: &Path, config: &Path, extra_args: &[&str]) -> Result<String> {
    let mut cmd = Command::new(deployer);
    cmd.arg("apply").arg("-f").arg(config);
    for arg in extra_args {
        cmd.arg(arg);
    }
    let output = cmd.output().context("failed to spawn deployer")?;
    if !output.status.success() {
        bail!(
            "deployer exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
