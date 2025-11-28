use greentic_conformance::FlowValidationOptions;
use std::fs;
use tempfile::tempdir;

const FLOW_WITHOUT_SCHEMA: &str = r#"
id: missing.schema
nodes:
  - id: start
    type: start
"#;

const FLOW_CUSTOM_EXTENSION: &str = r#"
id: custom.extension.flow
schema:
  version: 1
nodes:
  - id: start
    type: start
"#;

#[test]
fn flow_with_custom_extension_is_accepted_when_allowed() {
    let temp = tempdir().unwrap();
    let flow_path = temp.path().join("pipeline.flow");
    fs::write(&flow_path, FLOW_CUSTOM_EXTENSION).unwrap();

    let report = FlowValidationOptions::default()
        .allow_extension("flow")
        .validate_flow_folder(temp.path())
        .expect("custom extension to be accepted");

    assert_eq!(report.flows.len(), 1);
    assert_eq!(report.flows[0].id, "custom.extension.flow");
}

#[test]
fn missing_schema_can_be_allowed() {
    let temp = tempdir().unwrap();
    let flow_path = temp.path().join("noschema.ygtc");
    fs::write(&flow_path, FLOW_WITHOUT_SCHEMA).unwrap();

    let err = FlowValidationOptions::default()
        .require_schema(true)
        .validate_flow_folder(temp.path())
        .expect_err("explicit schema requirement should reject missing schema");
    let message = format!("{err:#}");
    assert!(
        message.contains("must declare a schema"),
        "unexpected error message: {message}"
    );

    let report = FlowValidationOptions::default()
        .allow_missing_schema()
        .validate_flow_folder(temp.path())
        .expect("missing schema allowed");

    assert_eq!(report.flows.len(), 1);
}
