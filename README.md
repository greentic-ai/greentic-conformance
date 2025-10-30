# Greentic Conformance

Reusable conformance harness for Greentic packs, flows, runners, and components. The crate exposes ergonomic helpers that downstream projects can import to standardise validation logic while keeping the actual runtime integrations local to the project under test.

## What It Covers

- **Pack suite** – Ensures pack assets ship a manifest with a signature and enumerated flows.
- **Flow suite** – Validates flow documents (e.g. `.ygtc`) for structural integrity and schema metadata.
- **Runner suite** – Boots a runner binary in mock mode, captures its output, and checks expected egress payloads.
- **Component suite** – Invokes a component in the generic component interface style, piping JSON input and asserting JSON output.

All suites return structured reports so higher-level tests can apply additional assertions or emit richer diagnostics.

## Getting Started

Add the crate to your workspace:

```toml
[dev-dependencies]
greentic-conformance = { path = "../greentic-conformance" }
```

Then exercise whichever suites you need from your integration tests:

```rust
use greentic_conformance::{validate_flow_folder, verify_pack_exports, PackSuiteOptions};

#[test]
fn pack_exports_are_well_formed() {
    let report = PackSuiteOptions::default()
        .with_runtime_adapter(|path| {
            // Swap this closure with a wasmtime-based adapter that calls list_flows.
            println!("Interrogating component: {}", path.display());
            Ok(vec!["example.flow".to_string()])
        })
        .verify_pack_exports("./packs/example/component.wasm")
        .unwrap();

    assert_eq!(report.runtime_flows.unwrap(), vec!["example.flow"]);
}

#[test]
fn flows_follow_schema() {
    let validation = validate_flow_folder("./flows").unwrap();
    assert_eq!(validation.flows.len(), 3);
}

#[test]
fn flows_with_custom_rules() {
    use anyhow::anyhow;
    use greentic_conformance::FlowValidationOptions;

    let options = FlowValidationOptions::default()
        .allow_extension("flow")
        .allow_missing_schema()
        .add_validator(|flow| {
            if flow.nodes.iter().any(|node| node.kind == "end") {
                Ok(())
            } else {
                Err(anyhow!("flow {} is missing an end node", flow.id))
            }
        });

    let validation = options.validate_flow_folder("./flows").unwrap();
    assert!(!validation.flows.is_empty());
}

#[test]
fn runner_smoke_test() {
    use greentic_conformance::{RunnerExpectation, RunnerOptions};
    use serde_json::json;

    let report = RunnerOptions::default()
        .add_arg("--mode")
        .add_arg("test")
        .with_expectation(
            RunnerExpectation::success()
                .require_json_stdout()
                .with_expected_egress(json!({ "disable_network": "1" })),
        )
        .smoke_run_with_mocks("./target/debug/greentic-runner", "./packs/example")
        .unwrap();

    assert_eq!(report.snapshot.status, 0);
}

#[test]
fn component_roundtrip() {
    use greentic_conformance::ComponentInvocationOptions;

    let invocation = ComponentInvocationOptions::default()
        .invoke_generic_component(
            "./target/debug/example-component",
            "echo",
            r#"{ "message": "hello" }"#,
        )
        .unwrap();

    assert_eq!(invocation.output_json.unwrap()["message"], "hello");
}
```

### Network Guardrails

The suites never enable network access implicitly. To opt-in for online checks (for example when a runner needs to hit remote connectors) set `GREENTIC_ENABLE_ONLINE=1` in your environment. Downstream harnesses can read this flag to decide whether to execute or skip online-dependent assertions.

### Runtime Integrations

- The pack suite accepts a `PackRuntimeAdapter` (for example a wasmtime loader) via `PackSuiteOptions::runtime_adapter`. When provided, it will call the adapter’s `list_flows` hook and ensure the runtime view matches the manifest.
- The flow suite exposes builder-style helpers on `FlowValidationOptions` so you can add file extensions, relax schema requirements, or register custom validators before calling `validate_flow_folder`.
- The runner suite forces mock-mode env vars by default; chain helpers like `.add_arg`, `.add_env`, and `.with_expectation` on `RunnerOptions` to tailor each smoke test.
- The component suite pipes JSON input via stdin and, by default, asserts that stdout is valid JSON. Call `.allow_non_json_output()` on `ComponentInvocationOptions` if your component returns another format.

## Development

- `cargo fmt` – style the codebase
- `cargo clippy -- -D warnings` – lint the crate
- `cargo test` – run the local test suite (no online access)

CI enforces all three commands. Online checks can be enabled via repository or environment configuration (see `.github/workflows/ci.yml`).

## License

Licensed under the [MIT License](LICENSE). Contributions are welcome under the same terms. 
