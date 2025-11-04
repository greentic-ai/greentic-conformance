mod common;

use common::TempBinary;
use greentic_conformance::{ComponentInvocationOptions, invoke_generic_component};

const COMPONENT_SOURCE: &str = r#"
use std::{env, io::{self, Read}};

fn main() {
    let mut args = env::args();
    let _binary = args.next();
    let operation = args.next().unwrap_or_default();

    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();

    match operation.as_str() {
        "echo" => {
            println!("{}", input.trim());
        }
        "raw" => {
            println!("not-json");
        }
        _ => {
            eprintln!("unknown operation: {operation}");
            std::process::exit(1);
        }
    }
}
"#;

#[test]
fn component_invocation_roundtrips_json() {
    let component = TempBinary::new("mock_component", COMPONENT_SOURCE);
    let invocation = invoke_generic_component(
        component.path().to_str().unwrap(),
        "echo",
        r#"{ "message": "hello" }"#,
    )
    .expect("component invocation to succeed");

    assert_eq!(invocation.status, 0);
    assert_eq!(invocation.output_json.unwrap()["message"], "hello");
}

#[test]
fn component_invocation_errors_on_non_json_output() {
    let component = TempBinary::new("mock_component_raw", COMPONENT_SOURCE);
    let error = invoke_generic_component(
        component.path().to_str().unwrap(),
        "raw",
        r#"{ "message": "hi" }"#,
    )
    .expect_err("component should fail JSON validation");

    assert!(
        error.to_string().contains("stdout is not valid JSON"),
        "unexpected error message: {error}"
    );
}

#[test]
fn component_invocation_can_allow_non_json() {
    let component = TempBinary::new("mock_component_non_json", COMPONENT_SOURCE);
    let report = ComponentInvocationOptions::default()
        .allow_non_json_output()
        .invoke_generic_component(component.path(), "raw", r#"{ "message": "ok" }"#)
        .expect("component invocation with non-json output to succeed");

    assert_eq!(report.stdout.trim(), "not-json");
}
