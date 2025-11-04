use greentic_conformance::{PackExport, PackManifest, PackSuiteOptions, verify_pack_exports};
use std::{fs::File, io::Write};
use tempfile::tempdir;

#[test]
fn pack_manifest_is_valid() {
    let temp = tempdir().unwrap();
    let pack_component = temp.path().join("mock-pack.component");
    File::create(&pack_component).unwrap();

    let manifest_path = temp.path().join("pack.manifest.json");
    let manifest = PackManifest {
        signature: "mock-signature".into(),
        flows: vec![PackExport {
            id: "example.flow".into(),
            summary: Some("Example flow".into()),
            schema: Some(serde_json::json!({
                "input": { "type": "object" },
                "output": { "type": "object" }
            })),
        }],
    };

    let mut file = File::create(&manifest_path).unwrap();
    write!(file, "{}", serde_json::to_string_pretty(&manifest).unwrap()).unwrap();

    // Exercise the default entrypoint
    let report =
        verify_pack_exports(pack_component.to_str().unwrap()).expect("pack verification to pass");
    assert_eq!(report.manifest.signature, "mock-signature");
    assert_eq!(report.manifest.flows.len(), 1);

    // Also ensure that the options path resolves correctly by pointing directly at the manifest.
    let pack_component_clone = pack_component.clone();

    let report_via_manifest = PackSuiteOptions::default()
        .with_runtime_adapter(
            move |component_path: &std::path::Path| -> anyhow::Result<Vec<String>> {
                assert_eq!(component_path, pack_component_clone.as_path());
                Ok(vec!["example.flow".into()])
            },
        )
        .with_manifest_override(manifest_path.clone())
        .verify_pack_exports(pack_component.to_str().unwrap())
        .expect("pack verification to pass with explicit manifest");

    assert_eq!(report_via_manifest.manifest.signature, "mock-signature");
    assert_eq!(
        report_via_manifest.runtime_flows.unwrap(),
        vec!["example.flow"]
    );
}
