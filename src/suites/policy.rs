use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use anyhow::{Result, anyhow};

use crate::{assertions, env::TenantContext};

/// Configuration for the policy conformance suite.
#[derive(Debug, Clone)]
pub struct PolicySuiteConfig {
    pub allowed_prefixes: Vec<String>,
    pub seeded_secrets: Vec<(String, String)>,
    pub denied_secrets: Vec<String>,
    pub idempotent_messages: Vec<(String, String)>,
    pub duplicate_message: Option<(String, String)>,
    pub retry_attempts: usize,
    pub retry_base_ms: u64,
}

impl Default for PolicySuiteConfig {
    fn default() -> Self {
        Self {
            allowed_prefixes: vec!["tenants/".to_string()],
            seeded_secrets: Vec::new(),
            denied_secrets: Vec::new(),
            idempotent_messages: Vec::new(),
            duplicate_message: None,
            retry_attempts: 3,
            retry_base_ms: 100,
        }
    }
}

impl PolicySuiteConfig {
    /// Builds a configuration using the canonical sample data from the fixtures.
    pub fn demonstration() -> Self {
        Self {
            allowed_prefixes: vec!["tenants/acme/".to_string()],
            seeded_secrets: vec![(
                "tenants/acme/db".to_string(),
                "postgres://user:pass@localhost/db".to_string(),
            )],
            denied_secrets: vec!["tenants/other/db".to_string()],
            idempotent_messages: vec![
                ("id-1".to_string(), "email".to_string()),
                ("id-2".to_string(), "sms".to_string()),
            ],
            duplicate_message: Some(("id-1".to_string(), "email".to_string())),
            retry_attempts: 3,
            retry_base_ms: 100,
        }
    }
}

/// Report returned after running the policy suite.
#[derive(Debug, Clone)]
pub struct PolicySuiteReport {
    pub tenant: TenantContext,
    pub granted_secrets: Vec<String>,
    pub denied_results: Vec<Result<String, String>>,
    pub idempotent_checked: usize,
    pub duplicate_detected: bool,
    pub retry_schedule: Vec<Duration>,
}

/// Executes the policy conformance suite with the provided configuration.
pub fn run_suite(config: PolicySuiteConfig) -> Result<PolicySuiteReport> {
    let tenant = TenantContext::detect()?;
    let PolicySuiteConfig {
        allowed_prefixes,
        seeded_secrets,
        denied_secrets,
        idempotent_messages,
        duplicate_message,
        retry_attempts,
        retry_base_ms,
    } = config;

    let mut secrets = AllowListSecrets::new(&allowed_prefixes);
    let mut granted = Vec::new();
    for (key, value) in &seeded_secrets {
        secrets.put(key, value);
        granted.push(key.clone());
    }

    let denied_results = denied_secrets
        .iter()
        .map(|key| match secrets.get(key) {
            Ok(_) => Err(format!(
                "secret {key} unexpectedly succeeded (expected access denied)"
            )),
            Err(err) => Ok(err.to_string()),
        })
        .collect::<Vec<_>>();

    assertions::assert_idempotent_send(
        idempotent_messages
            .iter()
            .map(|(id, kind)| (id.as_str(), kind.as_str())),
    )?;

    let duplicate_detected = if let Some(duplicate) = duplicate_message.clone() {
        let mut list = idempotent_messages.clone();
        list.push(duplicate.clone());
        assertions::assert_idempotent_send(
            list.iter().map(|(id, kind)| (id.as_str(), kind.as_str())),
        )
        .is_err()
    } else {
        false
    };

    let retry_schedule = compute_backoff_schedule(retry_attempts, retry_base_ms);

    Ok(PolicySuiteReport {
        tenant,
        granted_secrets: granted,
        denied_results,
        idempotent_checked: idempotent_messages.len(),
        duplicate_detected,
        retry_schedule,
    })
}

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
    fn new(allowed: &[String]) -> Self {
        Self {
            allowed_prefixes: allowed.iter().cloned().collect(),
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
