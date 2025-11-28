use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Metadata emitted by repo publication.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RepoPackDescriptor {
    pub pack_id: String,
    pub pack_version: String,
    #[serde(default)]
    pub digest: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub sbom: Option<String>,
}

/// Store subscription entry.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StoreSubscription {
    pub tenant: String,
    pub team: String,
    pub user: String,
    pub pack_id: String,
    pub pack_version: String,
    pub enabled: bool,
    #[serde(default)]
    pub policy: Option<String>,
}

/// Distributor target state entry.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DistributorTarget {
    pub pack_id: String,
    pub pack_version: String,
    pub enabled: bool,
}

/// Validates repo metadata for required fields and uniqueness.
pub fn validate_repo_metadata(descriptors: &[RepoPackDescriptor]) -> Result<()> {
    let mut seen = HashSet::new();
    for d in descriptors {
        if d.pack_id.trim().is_empty() {
            bail!("repo metadata entry missing pack_id");
        }
        if d.pack_version.trim().is_empty() {
            bail!("repo metadata entry missing pack_version for {}", d.pack_id);
        }
        let key = (d.pack_id.as_str(), d.pack_version.as_str());
        if !seen.insert(key) {
            bail!(
                "duplicate repo metadata entry for {} {}",
                d.pack_id,
                d.pack_version
            );
        }
    }
    Ok(())
}

/// Validates store subscriptions for required fields.
pub fn validate_store_subscriptions(subs: &[StoreSubscription]) -> Result<()> {
    for s in subs {
        if s.tenant.trim().is_empty() || s.team.trim().is_empty() || s.user.trim().is_empty() {
            bail!("store subscription must include tenant/team/user");
        }
        if s.pack_id.trim().is_empty() {
            bail!("store subscription missing pack_id");
        }
        if s.pack_version.trim().is_empty() {
            bail!("store subscription missing pack_version");
        }
    }
    Ok(())
}

/// Validates distributor target state against repo metadata and subscriptions.
pub fn validate_distributor_target(
    target: &[DistributorTarget],
    metadata: &[RepoPackDescriptor],
    subs: &[StoreSubscription],
) -> Result<()> {
    let allowed: HashSet<_> = metadata
        .iter()
        .map(|m| (m.pack_id.as_str(), m.pack_version.as_str()))
        .collect();
    let requested: HashSet<_> = subs
        .iter()
        .filter(|s| s.enabled)
        .map(|s| (s.pack_id.as_str(), s.pack_version.as_str()))
        .collect();

    let targets: HashSet<_> = target
        .iter()
        .filter(|t| t.enabled)
        .map(|t| (t.pack_id.as_str(), t.pack_version.as_str()))
        .collect();

    for (pid, ver) in &targets {
        if !allowed.contains(&(pid, ver)) {
            bail!("distributor target references unknown pack {}@{}", pid, ver);
        }
    }

    for (pid, ver) in &requested {
        if !targets.contains(&(pid, ver)) {
            bail!("distributor target missing requested pack {}@{}", pid, ver);
        }
    }

    Ok(())
}
