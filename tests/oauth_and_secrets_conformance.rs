use anyhow::Result;
use greentic_conformance::oauth_broker_suite::{
    BrokerTokenRequest, BrokerTokenResponse, validate_broker_request, validate_broker_response,
};
use serde_json::from_str;
use std::fs;

fn fixture(name: &str) -> String {
    let path = format!("fixtures/oauth/{}", name);
    fs::read_to_string(path).expect("fixture readable")
}

#[test]
fn test_broker_returns_token_for_valid_resource_and_scopes() -> Result<()> {
    let req: BrokerTokenRequest = from_str(&fixture("broker_request_valid.json"))?;
    validate_broker_request(&req)?;

    let res: BrokerTokenResponse = from_str(&fixture("broker_response_valid.json"))?;
    validate_broker_response(&res)?;
    Ok(())
}

#[test]
fn test_broker_returns_error_for_invalid_scope() {
    let req: BrokerTokenRequest = from_str(&fixture("broker_request_invalid_scope.json")).unwrap();
    let err = validate_broker_request(&req).unwrap_err();
    assert!(
        err.to_string().contains("scopes"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_broker_error_response_is_structured() -> Result<()> {
    let res: BrokerTokenResponse = from_str(&fixture("broker_response_error.json"))?;
    validate_broker_response(&res)?;
    Ok(())
}
