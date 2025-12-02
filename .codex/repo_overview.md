# Repository Overview

## 1. High-Level Purpose
Reusable conformance harness for the Greentic platform. The crate bundles suites that validate packs, flows, runners, components, policy/secret behaviour, OAuth flows, and repository metadata using shared fixtures and helpers. A CLI front-end exposes the same checks for downstream workspaces.

## 2. Main Components and Functionality
- **Path:** src/assertions.rs  
  - **Role:** Shared validation helpers for signatures, idempotent messaging, telemetry span attributes, and tenant/session identifiers.  
  - **Key functionality:** Asserts pack signature blocks, enforces idempotent message IDs, validates OTEL attributes (including semver pack version), and checks tenant/session IDs are non-empty.  
  - **Key dependencies / integration points:** Used across suites and CLI; feeds on serde_json values and semver parsing.
- **Path:** src/env.rs  
  - **Role:** Environment flag handling and tenant context detection.  
  - **Key functionality:** Truthy flag parsing, required env lookup with friendly errors, default tenant/team/user detection with CI enforcement, optional OTEL endpoint discovery, and validation hooks.
- **Path:** src/flow_suite.rs  
  - **Role:** Flow validation engine with configurable options and custom validators.  
  - **Key functionality:** Scans directories for flow files, parses YAML/JSON into typed documents, enforces schema/version rules, deduplicates node IDs, validates routing targets and MCP metadata, and distinguishes flow types (messaging/events/worker/digital worker).  
  - **Key dependencies / integration points:** Walkdir for discovery; serde_yaml/serde_json parsing; custom validators plug in via trait.
- **Path:** src/pack_suite.rs  
  - **Role:** Pack manifest verification and optional runtime export checks.  
  - **Key functionality:** Discovers manifest paths, parses YAML/JSON, validates pack metadata (ids, versions, flow entries, secrets, supply-chain fields), checks flow export uniqueness, ensures optional artifacts exist, and optionally compares runtime-exported flows via a user-supplied adapter.  
  - **Key dependencies / integration points:** Works with pack runtimes through `PackRuntimeAdapter`; used by CLI and higher-level suites.
- **Path:** src/component_suite.rs  
  - **Role:** Generic component invocation harness.  
  - **Key functionality:** Spawns component binaries with JSON stdin, enforces success/JSON stdout by default, supports env/args/working-dir overrides, and asserts exported worlds/tool invocations avoid denylisted entries or malformed metadata.
- **Path:** src/runner_suite.rs  
  - **Role:** Runner smoke-test harness.  
  - **Key functionality:** Launches runner binaries with mock-mode env defaults, optional stdin/args/env, validates exit status, parses stdout as JSON when requested, and compares expected egress fragments.
- **Path:** src/suites/pack_runner.rs  
  - **Role:** Composite suite that runs pack validation and optional runner smoke tests with shared tenant context.  
  - **Key functionality:** Reads env overrides, enforces manifest signatures unless disabled, invokes pack suite, and runs runner harness when configured.
- **Path:** src/suites/policy.rs  
  - **Role:** Policy/secret conformance checks using allow-list semantics.  
  - **Key functionality:** Seeds secrets, asserts denylist failures, enforces idempotent messaging, detects duplicates, and computes retry backoff schedules.
- **Path:** src/suites/oauth.rs  
  - **Role:** OAuth conformance suite covering mock and live providers.  
  - **Key functionality:** Spins up embedded Axum-based OIDC mock server, validates discovery/authorization/token flows, and optionally probes live providers (Google/Microsoft/GitHub) based on env-sourced credentials with graceful skips on network issues.  
  - **Key dependencies / integration points:** Axum, reqwest; uses env flags (`CI_ENABLE_OAUTH*`, `CI_DISABLE_OAUTH_MOCK`) to select lanes.
- **Path:** src/deployer_suite.rs  
  - **Role:** Idempotency check for deployer binaries.  
  - **Key functionality:** Runs `apply -f <config>` twice and compares outputs to ensure determinism.
- **Path:** src/events_suite.rs  
  - **Role:** Event provider and flow structure validation.  
  - **Key functionality:** Ensures provider definitions and event nodes include names/kinds/topics and reference known providers; validates subscription lifecycle handlers are present.
- **Path:** src/oauth_broker_suite.rs  
  - **Role:** OAuth broker request/response shape validation.  
  - **Key functionality:** Checks broker token requests for tenant/resource/scopes and enforces structured token/error responses.
- **Path:** src/repo_store_suite.rs  
  - **Role:** Repository/store metadata validation.  
  - **Key functionality:** Validates repo pack descriptors (ids/versions uniqueness), store subscriptions, and distributor targets align with available metadata and requested subscriptions.
- **Path:** src/bin/greentic-conformance.rs  
  - **Role:** CLI front-end exposing pack/flow/component/runner/deployer checks.  
  - **Key functionality:** Wraps pack validation (with signature policy control), validates flows with configurable extensions and schema requirements, verifies components (pack exports) and can invoke an operation with JSON stdin, exercises runner smoke tests with optional stdin/egress expectations, and can verify deployer idempotency when a config is provided; supports JSON/text output.
- **Path:** crates/oauth-mock  
  - **Role:** Standalone mock OAuth/OIDC provider crate used by tests.  
  - **Key functionality:** Configurable mock server with dynamic signing keys, discovery/authorize/token/jwks/device endpoints, client/user configuration, and token issuance supporting PKCE, refresh, and device codes; exposes builder for clients/users.  
  - **Key dependencies / integration points:** Axum router; used by OAuth suite/tests.
- **Path:** fixtures/ and src/fixtures/**  
  - **Role:** Sample packs, flows, repo metadata, OAuth broker payloads, and helper scripts/templates for tests and examples.  
  - **Key functionality:** Includes valid/invalid pack manifests, flow examples (messaging/events/worker/digital worker), repo store/distributor JSON, OAuth broker request/response fixtures, and embedded mock OIDC docker-compose/README content.
- **Path:** vendor/greentic-pack, vendor/greentic-oauth  
  - **Role:** Removed in favor of crates.io releases; workspace now relies on published `greentic-pack` and `greentic-oauth`.

## 3. Work In Progress, TODOs, and Stubs
- None noted; CLI subcommands and dependencies now use shipped implementations.

## 4. Broken, Failing, or Conflicting Areas
- None currently observed; `cargo test --workspace --all-features` passes locally.

## 5. Notes for Future Work
- None currently noted.
