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
    ComponentInvocation, ComponentInvocationOptions, invoke_generic_component,
};
pub use flow_suite::{
    FlowDocument, FlowNode, FlowValidationOptions, FlowValidationReport, FlowValidator,
    validate_flow_folder,
};
pub use pack_suite::{
    PackExport, PackManifest, PackReport, PackRuntimeAdapter, PackSuiteOptions,
    resolve_pack_manifest, verify_pack_exports,
};
pub use runner_suite::{
    RunnerExpectation, RunnerOptions, RunnerReport, RunnerSnapshot, smoke_run_with_mocks,
};
