# Mock OIDC Provider

This docker-compose stack starts a lightweight mock OIDC issuer for local development.

```bash
cd src/fixtures/oauth/mock-oidc
CI_ENABLE_OAUTH=true docker compose up
```

The conformance tests use discovery-only checks by default. Set `CI_ENABLE_OAUTH=true` to
exercise the live OAuth flow, or point the environment variable to a real sandbox issuer.
