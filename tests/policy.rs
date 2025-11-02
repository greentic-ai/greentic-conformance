#![cfg(feature = "policy")]

use anyhow::{anyhow, Result};
use greentic_conformance::assertions;
use greentic_conformance::env::{bool_flag, TenantContext};
use std::collections::{HashMap, HashSet};
use std::time::Duration;

fn compute_backoff_schedule(attempts: usize, base_ms: u64) -> Vec<Duration> {
    (0..attempts)
        .map(|i| Duration::from_millis(base_ms * (i as u64 + 1)))
        .collect()
}

struct AllowListSecrets {
    allowed_prefixes: HashSet<String>,
    backing_store: HashMap<String, String>,
}

impl AllowListSecrets {
    fn new(allowed: &[&str]) -> Self {
        Self {
            allowed_prefixes: allowed.iter().map(|p| p.to_string()).collect(),
            backing_store: HashMap::new(),
        }
    }

    fn put(&mut self, key: &str, value: &str) {
        self.backing_store
            .insert(key.to_string(), value.to_string());
    }

    fn get(&self, key: &str) -> Result<String> {
        if !self
            .allowed_prefixes
            .iter()
            .any(|prefix| key.starts_with(prefix))
        {
            return Err(anyhow!("access denied for key {key}"));
        }

        self.backing_store
            .get(key)
            .cloned()
            .ok_or_else(|| anyhow!("missing secret for {key}"))
    }
}

#[test]
fn tenant_allow_list_enforced() -> Result<()> {
    let tenant = TenantContext::detect()?;

    let mut secrets = AllowListSecrets::new(&["tenants/acme/"]);
    secrets.put("tenants/acme/db", "postgres://user:pass@localhost/db");

    let allowed = secrets.get("tenants/acme/db")?;
    assert!(allowed.contains("postgres"));

    let denied = secrets.get("tenants/other/db");
    assert!(denied.is_err());

    assert!(!tenant.tenant_id.is_empty());
    Ok(())
}

#[test]
fn idempotent_send_outbox() -> Result<()> {
    assertions::assert_idempotent_send([("id-1", "email"), ("id-2", "sms")])?;

    let duplicate = assertions::assert_idempotent_send([("id-1", "email"), ("id-1", "email")]);
    assert!(duplicate.is_err());

    Ok(())
}

#[test]
fn retry_backoff_applied() -> Result<()> {
    if bool_flag("CI_ENABLE_VAULT") {
        // In real CI, the provider implementations will exercise the actual retry logic.
    }

    let schedule = compute_backoff_schedule(3, 100);
    assert_eq!(
        schedule,
        vec![
            Duration::from_millis(100),
            Duration::from_millis(200),
            Duration::from_millis(300)
        ]
    );

    Ok(())
}
