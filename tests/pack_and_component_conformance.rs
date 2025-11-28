use anyhow::Result;
use greentic_conformance::{
    PackSuiteOptions, assert_allowed_worlds, assert_valid_tool_invocation, verify_pack_exports,
};
use serde_json::json;
use std::path::PathBuf;

fn fixture(path: &str) -> PathBuf {
    PathBuf::from("fixtures").join(path)
}

#[test]
fn test_valid_pack_passes_layout_and_signature_checks() -> Result<()> {
    let pack_dir = fixture("packs/valid_pack_with_components_and_flows");
    let report = PackSuiteOptions::default()
        .require_artifacts()
        .verify_pack_exports(pack_dir.to_str().unwrap())?;
    assert_eq!(report.manifest.flows.len(), 1);
    Ok(())
}

#[test]
fn test_pack_with_missing_component_ref_fails() {
    let pack_dir = fixture("packs/invalid_pack_missing_component");
    let err = PackSuiteOptions::default()
        .require_artifacts()
        .verify_pack_exports(pack_dir.to_str().unwrap())
        .unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("component path") || msg.contains("missing.wasm"),
        "unexpected error: {msg}"
    );
}

#[test]
fn test_pack_missing_signature_is_rejected() {
    let pack_dir = fixture("packs/invalid_pack_missing_signature");
    let err = verify_pack_exports(pack_dir.to_str().unwrap()).unwrap_err();
    assert!(
        err.to_string().contains("signature"),
        "expected signature error, got {err:?}"
    );
}

#[test]
fn test_pack_with_empty_secret_fails() {
    let pack_dir = fixture("packs/invalid_pack_missing_secret");
    let err = verify_pack_exports(pack_dir.to_str().unwrap()).unwrap_err();
    assert!(
        format!("{err:#}").contains("secrets"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_generic_component_rejects_repo_specific_worlds() {
    let worlds = vec!["greentic:repo-ui-actions/repo-ui-worker@1.0.0".to_string()];
    let err = assert_allowed_worlds(&worlds).unwrap_err();
    assert!(
        err.to_string().contains("forbidden world"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_mcp_tool_manifest_and_invoke_conform() -> Result<()> {
    assert_valid_tool_invocation("weather", "get", &json!({ "city": "Oslo" }))?;
    Ok(())
}
