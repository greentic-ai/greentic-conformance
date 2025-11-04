#![cfg(feature = "runner")]

use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey};
use greentic_conformance::assertions::{self, SpanRecord};
use greentic_conformance::fixtures::pack::{ECHO_TEMPLATE, FLOW_YAML, MANIFEST_YAML};
use greentic_conformance::suites::pack_runner::{PackRunnerSuiteConfig, run_suite};
use handlebars::Handlebars;
use rand::rngs::OsRng;
use serde_json::{Value, json};
use serde_yaml_bw::from_str as from_yaml;
use std::{collections::HashMap, fs};
use tempfile::tempdir;

fn sign_manifest(manifest: &Value) -> Result<Value> {
    let mut manifest = manifest.clone();
    let canonical = serde_json::to_vec(&manifest)?;

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let signature: Signature = signing_key.sign(&canonical);

    let signature_block = json!({
        "type": "ed25519",
        "public_key": STANDARD.encode(verifying_key.to_bytes()),
        "signature": STANDARD.encode(signature.to_bytes()),
    });

    let object = manifest
        .as_object_mut()
        .ok_or_else(|| anyhow!("manifest must be a JSON object"))?;
    object.insert("signature".to_string(), signature_block);
    Ok(manifest)
}

#[test]
fn pack_suite_runs_with_signed_fixture() -> Result<()> {
    let manifest: Value = from_yaml(MANIFEST_YAML)?;
    let signed = sign_manifest(&manifest)?;

    let temp = tempdir()?;
    let manifest_path = temp.path().join("pack.manifest.json");
    fs::write(&manifest_path, serde_json::to_vec_pretty(&signed)?)?;

    let report = run_suite(PackRunnerSuiteConfig::new(&manifest_path))?;
    assert!(report.pack_report.manifest.signature.is_some());
    assert_eq!(report.pack_report.manifest.flows.len(), 1);

    Ok(())
}

#[test]
fn pack_suite_allows_unsigned_when_configured() -> Result<()> {
    let unsigned: Value = from_yaml(MANIFEST_YAML)?;
    let temp = tempdir()?;
    let manifest_path = temp.path().join("pack.manifest.json");
    fs::write(&manifest_path, serde_json::to_vec_pretty(&unsigned)?)?;

    let report = run_suite(PackRunnerSuiteConfig::new(&manifest_path).allow_unsigned())?;
    assert!(report.pack_report.manifest.signature.is_none());

    Ok(())
}

#[test]
fn flow_fixture_renders_and_spans_validate() -> Result<()> {
    let flow: Value = from_yaml(FLOW_YAML)?;
    let nodes = flow
        .get("nodes")
        .and_then(|value| value.as_array())
        .ok_or_else(|| anyhow!("flow missing nodes"))?;
    assert_eq!(nodes.len(), 4, "echo flow contains the expected steps");

    let mut handlebars = Handlebars::new();
    handlebars.register_template_string("echo", ECHO_TEMPLATE)?;

    let rendered = handlebars.render("echo", &json!({ "text": "hello" }))?;
    assert_eq!(rendered.trim(), "Echo: hello");

    assertions::assert_idempotent_send(["outbound-message-1"])?;

    let mut attrs = HashMap::new();
    attrs.insert("tenant".to_string(), json!("acme"));
    attrs.insert("session".to_string(), json!("session-123"));
    attrs.insert("flow".to_string(), json!("echo-flow"));
    attrs.insert("node".to_string(), json!("send"));
    attrs.insert("provider".to_string(), json!("mock"));

    assertions::assert_span_attrs(&[SpanRecord::new("flow", attrs)])?;

    Ok(())
}
