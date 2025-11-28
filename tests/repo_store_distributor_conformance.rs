use anyhow::Result;
use greentic_conformance::repo_store_suite::{
    DistributorTarget, RepoPackDescriptor, StoreSubscription, validate_distributor_target,
    validate_repo_metadata, validate_store_subscriptions,
};
use serde_json::from_str;
use std::fs;

fn fixture(name: &str) -> String {
    let path = format!("fixtures/repo_store/{}", name);
    fs::read_to_string(path).expect("fixture readable")
}

#[test]
fn test_repo_metadata_conformance() -> Result<()> {
    let metadata: Vec<RepoPackDescriptor> = from_str(&fixture("repo_metadata_valid.json"))?;
    validate_repo_metadata(&metadata)?;
    Ok(())
}

#[test]
fn test_missing_pack_in_repo_metadata_fails() {
    let metadata: Vec<RepoPackDescriptor> =
        from_str(&fixture("repo_metadata_missing_pack.json")).unwrap();
    let err = validate_repo_metadata(&metadata).unwrap_err();
    assert!(
        err.to_string().contains("pack_id"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_store_subscription_has_required_fields() -> Result<()> {
    let subs: Vec<StoreSubscription> = from_str(&fixture("store_subscriptions_valid.json"))?;
    validate_store_subscriptions(&subs)?;
    Ok(())
}

#[test]
fn test_store_subscription_invalid() {
    let subs: Vec<StoreSubscription> =
        from_str(&fixture("store_subscriptions_invalid.json")).unwrap();
    let err = validate_store_subscriptions(&subs).unwrap_err();
    assert!(
        err.to_string().contains("tenant"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_distributor_target_matches_store_subscriptions() -> Result<()> {
    let metadata: Vec<RepoPackDescriptor> = from_str(&fixture("repo_metadata_valid.json"))?;
    let subs: Vec<StoreSubscription> = from_str(&fixture("store_subscriptions_valid.json"))?;
    let target: Vec<DistributorTarget> = from_str(&fixture("distributor_target_valid.json"))?;
    validate_distributor_target(&target, &metadata, &subs)?;
    Ok(())
}

#[test]
fn test_distributor_target_missing_requested_pack_fails() {
    let metadata: Vec<RepoPackDescriptor> = from_str(&fixture("repo_metadata_valid.json")).unwrap();
    let subs: Vec<StoreSubscription> =
        from_str(&fixture("store_subscriptions_valid.json")).unwrap();
    let target: Vec<DistributorTarget> =
        from_str(&fixture("distributor_target_missing.json")).unwrap();
    let err = validate_distributor_target(&target, &metadata, &subs).unwrap_err();
    assert!(
        err.to_string().contains("missing requested pack")
            || err.to_string().contains("unknown pack"),
        "unexpected error: {err:?}"
    );
}
