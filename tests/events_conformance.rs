use anyhow::Result;
use greentic_conformance::events_suite::{
    EventFlow, EventProvider, SubscriptionLifecycle, validate_event_flow, validate_provider,
    validate_subscription_lifecycle,
};
use serde_json::from_str;
use std::fs;

fn fixture(name: &str) -> String {
    let path = format!("fixtures/events/{}", name);
    fs::read_to_string(path).expect("fixture readable")
}

#[test]
fn test_events_flow_with_valid_providers_passes() -> Result<()> {
    let providers: Vec<EventProvider> = from_str(&fixture("providers_valid.json"))?;
    let flow: EventFlow = from_str(&fixture("event_flow_valid.json"))?;
    validate_event_flow(&flow, &providers)?;
    Ok(())
}

#[test]
fn test_events_flow_with_missing_provider_fails() {
    let providers: Vec<EventProvider> = from_str(&fixture("providers_valid.json")).unwrap();
    let flow: EventFlow = from_str(&fixture("event_flow_missing_provider.json")).unwrap();
    let err = validate_event_flow(&flow, &providers).unwrap_err();
    assert!(
        err.to_string().contains("missing provider"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_provider_validation_catches_empty_name() {
    let providers: Vec<EventProvider> =
        from_str(&fixture("providers_invalid_missing_name.json")).expect("fixture parses");
    let err = validate_provider(&providers[0]).unwrap_err();
    assert!(
        err.to_string().contains("name"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_subscription_lifecycle_is_complete() -> Result<()> {
    let lifecycle: SubscriptionLifecycle = from_str(&fixture("subscription_lifecycle_valid.json"))?;
    validate_subscription_lifecycle(&lifecycle)?;
    Ok(())
}

#[test]
fn test_subscription_lifecycle_missing_delete_fails() {
    let lifecycle: SubscriptionLifecycle =
        from_str(&fixture("subscription_lifecycle_missing_delete.json")).unwrap();
    let err = validate_subscription_lifecycle(&lifecycle).unwrap_err();
    assert!(
        err.to_string().contains("delete"),
        "unexpected error: {err:?}"
    );
}
