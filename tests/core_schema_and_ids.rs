use std::collections::HashMap;

use anyhow::Result;
use greentic_conformance::{
    FlowDocument, FlowNode, FlowSchemaVersion, PackManifest, PackSchemaVersion,
    assertions::{assert_otel_attributes, assert_valid_session_ids, assert_valid_tenant_ctx},
    detect_flow_schema_version, detect_pack_schema_version,
};
use serde_json::json;

#[test]
fn test_pack_schema_version_supported() -> Result<()> {
    let manifest = PackManifest {
        schema_version: Some("v1".into()),
        version: Some("1.0.0".into()),
        id: Some("pack-1".into()),
        ..PackManifest::default()
    };

    let version = detect_pack_schema_version(&manifest)?;
    assert_eq!(version, PackSchemaVersion::V1);
    Ok(())
}

#[test]
fn test_pack_schema_version_unknown_fails() {
    let manifest = PackManifest {
        schema_version: Some("v2".into()),
        version: Some("1.0.0".into()),
        id: Some("pack-1".into()),
        ..PackManifest::default()
    };

    let err = detect_pack_schema_version(&manifest).unwrap_err();
    assert!(
        err.to_string().contains("unknown pack schema version"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_flow_schema_version_supported() -> Result<()> {
    let flow = FlowDocument {
        id: "flow-1".into(),
        r#type: None,
        name: None,
        summary: None,
        schema_version: Some("1".into()),
        schema_ref: None,
        schema: None,
        nodes: vec![FlowNode {
            id: "n1".into(),
            kind: "noop".into(),
            route: None,
            description: None,
            metadata: None,
        }],
    };

    let version = detect_flow_schema_version(&flow)?;
    assert_eq!(version, FlowSchemaVersion::V1);
    Ok(())
}

#[test]
fn test_flow_schema_version_unknown_fails() {
    let flow = FlowDocument {
        id: "flow-1".into(),
        r#type: None,
        name: None,
        summary: None,
        schema_version: Some("flow.v2".into()),
        schema_ref: None,
        schema: None,
        nodes: vec![FlowNode {
            id: "n1".into(),
            kind: "noop".into(),
            route: None,
            description: None,
            metadata: None,
        }],
    };

    let err = detect_flow_schema_version(&flow).unwrap_err();
    assert!(
        err.to_string().contains("unknown flow schema version"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_tenant_and_session_ids_are_valid() -> Result<()> {
    assert_valid_tenant_ctx("tenant-1", "team-1", "user-1")?;
    assert_valid_session_ids("session-1", Some("corr-1"), Some("thread-1"))?;
    Ok(())
}

#[test]
fn test_telemetry_span_contains_expected_keys() -> Result<()> {
    let mut attrs: HashMap<String, serde_json::Value> = HashMap::new();
    attrs.insert("service.name".into(), json!("greentic-runner"));
    attrs.insert("greentic.pack.id".into(), json!("pack-123"));
    attrs.insert("greentic.pack.version".into(), json!("1.2.3"));
    attrs.insert("greentic.flow.id".into(), json!("flow-1"));
    attrs.insert("greentic.node.id".into(), json!("node-1"));
    attrs.insert("greentic.component.name".into(), json!("component"));
    attrs.insert("greentic.component.version".into(), json!("0.1.0"));
    attrs.insert("greentic.tenant.id".into(), json!("tenant-1"));
    attrs.insert("greentic.team.id".into(), json!("team-1"));
    attrs.insert("greentic.user.id".into(), json!("user-1"));
    attrs.insert("greentic.session.id".into(), json!("session-1"));
    attrs.insert("greentic.run.status".into(), json!("ok"));
    attrs.insert("greentic.capability".into(), json!("flow"));
    attrs.insert("greentic.artifacts.dir".into(), json!("/tmp"));

    assert_otel_attributes(&attrs)?;
    Ok(())
}
