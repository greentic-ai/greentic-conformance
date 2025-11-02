#![cfg(feature = "runner")]

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey};
use greentic_conformance::assertions::{self, SpanRecord};
use greentic_conformance::env::{bool_flag, TenantContext};
use greentic_conformance::fixtures::pack::{ECHO_TEMPLATE, FLOW_YAML, MANIFEST_YAML};
use handlebars::Handlebars;
use rand::rngs::OsRng;
use serde_json::json;
use serde_json::Value;
use serde_yaml::from_str as from_yaml;
use std::collections::HashMap;

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

#[tokio::test]
async fn build_and_sign_pack() -> Result<()> {
    let manifest: Value = from_yaml(MANIFEST_YAML)?;
    let signed = sign_manifest(&manifest)?;

    assertions::assert_signed_pack(&signed)?;
    Ok(())
}

#[tokio::test]
async fn runner_loads_signed_pack() -> Result<()> {
    let tenant = TenantContext::detect()?;
    assert!(!tenant.tenant_id.is_empty());

    let unsigned: Value = from_yaml(MANIFEST_YAML)?;
    assert!(assertions::assert_signed_pack(&unsigned).is_err());

    let signed = sign_manifest(&unsigned)?;
    assertions::assert_signed_pack(&signed)?;

    // Simulate ALLOW_UNSIGNED override for local workflows.
    std::env::set_var("ALLOW_UNSIGNED", "true");
    assert!(bool_flag("ALLOW_UNSIGNED"));
    std::env::remove_var("ALLOW_UNSIGNED");

    Ok(())
}

#[tokio::test]
async fn run_simple_flow_end_to_end() -> Result<()> {
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
