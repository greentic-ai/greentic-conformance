use anyhow::{Result, bail};
use greentic_conformance::{FlowDocument, FlowValidationOptions};
use std::fs;
use tempfile::tempdir;

const FLOW_SIMPLE: &str = r#"
id: validator.flow
schema:
  version: 1
nodes:
  - id: start
    type: start
  - id: end
    type: end
"#;

#[test]
fn custom_validator_can_enforce_additional_rules() {
    let temp = tempdir().unwrap();
    let flow_path = temp.path().join("custom.ygtc");
    fs::write(&flow_path, FLOW_SIMPLE).unwrap();

    let options = FlowValidationOptions::default().add_validator(|flow: &FlowDocument| {
        let has_end = flow.nodes.iter().any(|node| node.kind == "end");
        if has_end {
            Ok(())
        } else {
            bail!("flow {} must contain an end node", flow.id);
        }
    });

    options
        .validate_flow_folder(temp.path())
        .expect("validator to approve flow with end node");
}

#[test]
fn custom_validator_failure_surfaces_error() {
    let temp = tempdir().unwrap();
    let flow_path = temp.path().join("missing-end.ygtc");
    fs::write(
        &flow_path,
        r#"
id: missing.end.flow
schema:
  version: 1
nodes:
  - id: start
    type: start
"#,
    )
    .unwrap();

    let options =
        FlowValidationOptions::default().add_validator(|flow: &FlowDocument| -> Result<()> {
            if flow.nodes.iter().any(|node| node.kind == "end") {
                Ok(())
            } else {
                bail!("flow {} must contain an end node", flow.id);
            }
        });

    let err = options
        .validate_flow_folder(temp.path())
        .expect_err("validator should reject flow without end node");
    let message = format!("{err:#}");
    assert!(message.contains("must contain an end node"));
}
