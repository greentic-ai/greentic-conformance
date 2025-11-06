# Conformance Coverage

| Plan slug | Suite plan name | Focus | Greentic RP features exercised | Where to look |
|-----------|----------------|-------|--------------------------------|---------------|
| `rp-code-pkce-basic` | `oidcc-client-basic-certification-test-plan` | Baseline RP code flow with PKCE and state handling | OAuth shim (`src/shims.rs::oauth`), embedded mock server (`crates/oauth-mock`) | `tests/oauth.rs`, `ci/scripts/run_conformance_plan.sh` |
| `rp-fapi1-advanced` | `fapi1-advanced-final-client-test-plan` | Financial-grade API (FAPI) 1.0 Advanced profile with PAR/JAR requirements | Request object ingestion, pushed authorization endpoint, RS256 verification | `ci/scripts/run_conformance_plan.sh`, `ci/docker/rp_app.py`, `src/shims.rs::oauth` |
| `rp-fapi2-message-signing` | `fapi2-message-signing-id1-client-test-plan` | FAPI 2.0 with JARM response signing and sender-constrained tokens | JARM/JWT validation, audience binding, DPoP-aware request signing | `ci/scripts/run_conformance_plan.sh`, `crates/oauth-mock/src/lib.rs` (signing keys), `tests/provider_google.rs` |
| `rp-par-jar-dpop` | `fapi2-security-profile-id2-client-test-plan` | Pushed Authorization Requests + JWT Authorization Requests with DPoP proof | DPoP proof verification, request object JWT parsing, token endpoint binding | `ci/scripts/run_conformance_plan.sh`, `ci/docker/rp_app.py`, `tests/provider_azure.rs` |

The [`ci/docker/compose.conformance.yml`](../ci/docker/compose.conformance.yml) stack enables additional suite features by setting `FINANCIAL_API=true`. Nightly runs iterate over the plans above and publish artifacts under `reports/` (see README “Artifacts”).
