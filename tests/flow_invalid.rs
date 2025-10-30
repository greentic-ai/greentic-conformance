use greentic_conformance::validate_flow_folder;
use std::fs;
use tempfile::tempdir;

#[test]
fn invalid_flow_is_rejected() {
    let temp = tempdir().unwrap();
    let flow_path = temp.path().join("broken.ygtc");
    fs::write(
        &flow_path,
        r#"
id: invalid.flow
name: Broken Flow
schema: null
nodes: []
"#,
    )
    .unwrap();

    let error = validate_flow_folder(temp.path().to_str().unwrap())
        .expect_err("flow validation should fail");
    let message = format!("{error:#}");
    assert!(
        message.contains("must declare a schema")
            || message.contains("must declare at least one node"),
        "unexpected error message: {message}"
    );
}
