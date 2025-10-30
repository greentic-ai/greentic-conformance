mod common;

use common::TempBinary;
use greentic_conformance::{RunnerExpectation, RunnerOptions};
use serde_json::json;
use std::fs;
use tempfile::tempdir;

const RUNNER_SOURCE: &str = r#"
use std::env;

fn escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            other => out.push(other),
        }
    }
    out
}

fn main() {
    let disable = escape(&env::var("GREENTIC_DISABLE_NETWORK").unwrap_or_default());
    let pack_path = escape(&env::var("GREENTIC_PACK_PATH").unwrap_or_default());
    let args: Vec<String> = env::args().skip(2).collect();
    let mut args_json = String::new();
    for (idx, arg) in args.iter().enumerate() {
        if idx > 0 {
            args_json.push(',');
        }
        args_json.push('"');
        args_json.push_str(&escape(arg));
        args_json.push('"');
    }

    println!(
        "{{\"disable_network\":\"{}\",\"pack_path\":\"{}\",\"args\":[{}]}}",
        disable, pack_path, args_json
    );
}
"#;

#[test]
fn runner_smoke_captures_mock_output() {
    let temp = tempdir().unwrap();
    let pack_path = temp.path().join("mock-pack.component");
    fs::write(&pack_path, b"pack-bytes").unwrap();

    let runner = TempBinary::new("mock_runner", RUNNER_SOURCE);

    let report = RunnerOptions::default()
        .add_arg("--mode")
        .add_arg("test")
        .with_expectation(
            RunnerExpectation::success()
                .require_json_stdout()
                .with_expected_egress(json!({
                    "disable_network": "1",
                    "args": ["--mode", "test"],
                    "pack_path": pack_path.to_string_lossy(),
                })),
        )
        .smoke_run_with_mocks(runner.path(), pack_path.to_str().expect("pack path utf8"))
        .expect("runner smoke test to pass");

    assert_eq!(report.snapshot.status, 0);
    let stdout = report.snapshot.stdout_json.expect("parsed JSON stdout");
    assert_eq!(stdout["disable_network"], "1");
}
