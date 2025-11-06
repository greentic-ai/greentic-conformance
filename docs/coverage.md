# Conformance Coverage

| Plan slug | Suite plan name | Focus | Greentic RP features exercised | Where to look |
|-----------|----------------|-------|--------------------------------|---------------|
| `rp-code-pkce-basic` | `oidcc-client-basic-certification-test-plan` | Baseline RP code flow with PKCE and state handling | OAuth shim (`src/shims.rs::oauth`), hosted conformance harness | `tests/oauth.rs`, `ci/scripts/run_conformance_hosted_with_tunnel.sh` |
| `rp-fapi1-advanced` | `fapi1-advanced-final-client-test-plan` | Financial-grade API (FAPI) 1.0 Advanced profile with PAR/JAR requirements | Request object ingestion, pushed authorization endpoint, RS256 verification | `ci/scripts/run_conformance_hosted_with_tunnel.sh`, `src/shims.rs::oauth` |
| `rp-fapi2-message-signing` | `fapi2-message-signing-id1-client-test-plan` | FAPI 2.0 with JARM response signing and sender-constrained tokens | JARM/JWT validation, audience binding, DPoP-aware request signing | `ci/scripts/run_conformance_hosted_with_tunnel.sh`, `crates/oauth-mock/src/lib.rs` (signing keys), `tests/provider_google.rs` |
| `rp-par-jar-dpop` | `fapi2-security-profile-id2-client-test-plan` | Pushed Authorization Requests + JWT Authorization Requests with DPoP proof | DPoP proof verification, request object JWT parsing, token endpoint binding | `ci/scripts/run_conformance_hosted_with_tunnel.sh`, `tests/provider_azure.rs` |
