use anyhow::Result;
use std::env;
use std::path::PathBuf;
use std::process::Command;

fn find_binary(name: &str) -> Option<PathBuf> {
    env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths).find_map(|dir| {
            let candidate = dir.join(name);
            if candidate.exists() {
                Some(candidate)
            } else {
                None
            }
        })
    })
}

#[test]
fn runner_help_smoke() -> Result<()> {
    let Some(runner) = find_binary("greentic-runner") else {
        // Skip if runner not installed.
        return Ok(());
    };
    let output = Command::new(runner).arg("--help").output()?;
    assert!(
        output.status.success(),
        "runner --help should succeed (status {:?})",
        output.status
    );
    Ok(())
}

#[test]
fn runner_with_invalid_bindings_fails() {
    let Some(runner) = find_binary("greentic-runner") else {
        return;
    };
    let bindings = "fixtures/runner/bindings_invalid.yaml";
    let output = Command::new(runner)
        .arg("--bindings")
        .arg(bindings)
        .output();
    if let Ok(out) = output {
        assert!(
            !out.status.success(),
            "runner should fail with invalid bindings file"
        );
    }
}
