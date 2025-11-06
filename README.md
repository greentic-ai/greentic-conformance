# Greentic Conformance

Reusable conformance harness for Greentic packs, flows, runners, and components. The crate exposes ergonomic helpers that downstream projects can import to standardise validation logic while keeping the actual runtime integrations local to the project under test.

## What We Test

The harness focuses on four areas that map directly to `greentic_conformance::suites::*`:

- **Pack suite** – validates manifest signatures, enumerated flows, and runtime exports for Greentic packs.
- **Flow suite** – parses and lint-checks flow documents (YAML/JSON) with optional custom validators.
- **Runner suite** – boots a runner binary in mock mode and inspects emitted telemetry / egress payloads.
- **OAuth suite** – delivers a deterministic mock OIDC server and can optionally exercise live providers when credentials are available.

Example usage lives in `tests/pack_runner.rs`, `tests/policy.rs`, and `tests/oauth.rs`. Downstream crates can copy those tests or import the suites directly.

### Shared helpers

Every suite builds on the reusable utilities under `src/`:

- `env.rs` – consistent parsing of multi-tenant IDs and CI feature flags (`CI_ENABLE_VAULT`, `CI_ENABLE_AWS`, `CI_ENABLE_GCP`, `CI_ENABLE_OAUTH_MOCK`, `CI_ENABLE_OAUTH_LIVE`, `CI_DISABLE_OAUTH_MOCK`, `ALLOW_UNSIGNED`, `OTEL_EXPORTER_OTLP_ENDPOINT`, `TENANT_ID`, `TEAM_ID`, `USER_ID`).
- `assertions.rs` – helpers such as `assert_signed_pack`, `assert_idempotent_send`, and `assert_span_attrs`.
- `fixtures/` – demo pack assets, signing utilities, and the embedded mock OIDC stack.

Typical harness usage:

```rust
use greentic_conformance::suites::pack_runner::{run_suite, PackRunnerSuiteConfig};

#[test]
fn pack_manifest_is_signed() {
    let report = run_suite(PackRunnerSuiteConfig::new("./packs/example/pack.manifest.json"))
        .expect("pack suite to succeed");
    assert!(report.pack_report.manifest.signature.is_some());
}

use greentic_conformance::suites::policy::{run_suite as run_policy_suite, PolicySuiteConfig};

#[test]
fn policy_contracts_hold() {
    let report = run_policy_suite(PolicySuiteConfig::demonstration()).unwrap();
    assert!(report.duplicate_detected);
}

use greentic_conformance::suites::oauth::{run_suite as run_oauth_suite, OAuthSuiteConfig};

#[tokio::test]
async fn oauth_mock_flow() {
    let config = OAuthSuiteConfig { run_mock: true, run_live: false, live_providers: Vec::new() };
    let report = run_oauth_suite(config).await.unwrap();
    assert!(report
        .outcomes
        .iter()
        .any(|outcome| outcome.name == "oauth:mock"));
}
```

## Environment Flags

- `TENANT_ID`, `TEAM_ID`, `USER_ID` – required in CI; local defaults (`local-*`) provided for convenience.
- `CI_ENABLE_VAULT`, `CI_ENABLE_AWS`, `CI_ENABLE_GCP` – toggle provider-specific policy checks.
- `ALLOW_UNSIGNED` – opt-in flag to accept unsigned packs during local development.
- `CI_DISABLE_OAUTH_MOCK` – skip the embedded mock OIDC provider even when the OAuth suite runs.
- `CI_ENABLE_OAUTH_MOCK` / `CI_ENABLE_OAUTH` – force the mock OAuth checks on in CI runs.
- `CI_ENABLE_OAUTH_LIVE` – enable the live provider lane when credentials are present.
- `OAUTH_{PROVIDER}_{CLIENT_ID,CLIENT_SECRET,REDIRECT_URI}` – provider specific secrets for Google, Microsoft, or GitHub (for example `OAUTH_GOOGLE_CLIENT_ID`). Optional overrides exist for `AUTH_URL`, `TOKEN_URL`, and `SCOPES`.
- `OTEL_EXPORTER_OTLP_ENDPOINT` – optional telemetry sink; when set, span assertions expect `{tenant, session, flow, node, provider}` attributes.

## CI Integration

The default workflow runs a three-lane matrix:

- `unit` – `cargo fmt`, `cargo clippy`, and `cargo test --workspace --all-features`.
- `oauth-mock` – targeted `cargo test --test oauth` with the embedded provider.
- `oauth-live` – re-runs the OAuth suite with `CI_ENABLE_OAUTH_LIVE=1` when any live provider secrets are present (`OAUTH_*_CLIENT_ID`).

Downstream repositories can mirror the same lanes or mix-and-match harness calls. Extra provider secrets can be injected with the environment keys listed above; when no credentials are available the live lane is skipped automatically.

## Profiles

The OIDF conformance suite publishes many RP profiles. We track the plans we care about in [`docs/coverage.md`](docs/coverage.md); each entry documents the plan slug, the features it covers in the Greentic RP client, and where to inspect the harness implementation.

Our CI defaults to `rp-code-pkce-basic` for fast feedback, while nightly jobs opt into stricter plans such as FAPI1/FAPI2, PAR/JAR, and DPoP. Use the coverage table to understand which areas are exercised before adding new flows.

## Hosted OIDF Conformance

We run RP plans against the hosted OpenID Foundation conformance suite. See
[`docs/oidf_conformance.md`](docs/oidf_conformance.md) for the end-to-end flow,
including the Cloudflare tunnel helper for local development and the GitHub
Actions workflow for CI runs.

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

## Releases & Publishing

- Versions are sourced from each crate’s `Cargo.toml`.
- Pushing to `master` auto-tags crates whose versions changed using `<crate>-v<version>`.
- The publish workflow then pushes updated crates to crates.io.
- Publishing is idempotent and succeeds even when versions already exist.

## License

Licensed under the [MIT License](LICENSE). Contributions are welcome under the same terms. 
