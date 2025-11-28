pub mod assertions;
pub mod env;
pub mod shims;
pub mod suites;

pub mod fixtures {
    pub mod pack {
        pub const MANIFEST_YAML: &str = include_str!("fixtures/pack/pack.yaml");
        pub const FLOW_YAML: &str = include_str!("fixtures/pack/flow.yaml");
        pub const TOOLMAP_JSON: &str = include_str!("fixtures/pack/toolmap.json");
        pub const ECHO_TEMPLATE: &str = include_str!("fixtures/pack/templates/echo.hbs");
    }

    pub mod keys {
        pub const DEV_ED25519_GENERATOR: &str =
            include_str!("fixtures/keys/dev-ed25519-generate.rs");
    }

    pub mod oauth {
        pub const DOCKER_COMPOSE: &str =
            include_str!("fixtures/oauth/mock-oidc/docker-compose.yml");
        pub const README: &str = include_str!("fixtures/oauth/mock-oidc/README.md");
    }
}

mod component_suite;
mod flow_suite;
mod pack_suite;
mod runner_suite;

pub use component_suite::{
    ComponentInvocation, ComponentInvocationOptions, assert_allowed_worlds,
    assert_valid_tool_invocation, invoke_generic_component,
};
pub mod deployer_suite;
pub mod events_suite;
pub mod oauth_broker_suite;
pub mod repo_store_suite;
pub use flow_suite::{
    FlowDocument, FlowNode, FlowSchemaVersion, FlowValidationOptions, FlowValidationReport,
    FlowValidator, detect_flow_schema_version, validate_flow_folder,
};
pub use pack_suite::{
    PackExport, PackManifest, PackReport, PackRuntimeAdapter, PackSchemaVersion, PackSignature,
    PackSuiteOptions, detect_pack_schema_version, resolve_pack_manifest, verify_pack_exports,
};
pub use runner_suite::{
    RunnerExpectation, RunnerOptions, RunnerReport, RunnerSnapshot, smoke_run_with_mocks,
};
