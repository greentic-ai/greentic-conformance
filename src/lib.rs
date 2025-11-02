pub mod assertions;
pub mod env;

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
    invoke_generic_component, ComponentInvocation, ComponentInvocationOptions,
};
pub use flow_suite::{
    validate_flow_folder, FlowDocument, FlowNode, FlowValidationOptions, FlowValidationReport,
    FlowValidator,
};
pub use pack_suite::{
    resolve_pack_manifest, verify_pack_exports, PackExport, PackManifest, PackReport,
    PackRuntimeAdapter, PackSuiteOptions,
};
pub use runner_suite::{
    smoke_run_with_mocks, RunnerExpectation, RunnerOptions, RunnerReport, RunnerSnapshot,
};
