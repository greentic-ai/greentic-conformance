#![cfg(feature = "policy")]

use anyhow::Result;
use greentic_conformance::suites::policy::{PolicySuiteConfig, run_suite};

#[test]
fn policy_suite_demonstration_passes() -> Result<()> {
    let report = run_suite(PolicySuiteConfig::demonstration())?;

    assert_eq!(report.granted_secrets, vec!["tenants/acme/db".to_string()]);
    assert_eq!(report.idempotent_checked, 2);
    assert!(report.duplicate_detected);
    assert_eq!(report.retry_schedule.len(), 3);
    assert!(
        report
            .retry_schedule
            .iter()
            .map(|duration| duration.as_millis())
            .eq([100, 200, 300])
    );
    assert!(
        report
            .denied_results
            .iter()
            .all(|result| result.as_ref().is_ok())
    );

    Ok(())
}

#[test]
fn policy_suite_handles_custom_inputs() -> Result<()> {
    let mut config = PolicySuiteConfig::demonstration();
    config.denied_secrets.clear();
    config.idempotent_messages = vec![("id-1".into(), "email".into())];
    config.duplicate_message = None;

    let report = run_suite(config)?;
    assert_eq!(report.denied_results.len(), 0);
    assert!(!report.duplicate_detected);

    Ok(())
}
