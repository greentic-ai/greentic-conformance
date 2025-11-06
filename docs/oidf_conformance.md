# OIDF Conformance Quickstart

Run the OpenID Foundation RP conformance suite end-to-end with a single make
command. This guide covers environment requirements, supported variants, and
common troubleshooting steps.

## Prerequisites

- **Suite URL & token** – create an API token in the OIDF Conformance Suite UI
  and note the base URL (e.g. `https://www.certification.openid.net`).
- **Reachable RP callback** – the suite must be able to hit your relying party
  at the configured redirect URI (default stub: `python ci/docker/rp_app.py`).
- **RP metadata URL** – the plan runner needs either your `.well-known`
  metadata URL or a stub endpoint exposed by the RP harness.

Export these before running the automation:

```bash
export CS_URL="https://www.certification.openid.net"
export CS_TOKEN="***"
export RP_METADATA_URL="https://your-rp/.well-known/openid-configuration"
export RP_TRIGGER_URL="https://your-rp/_conformance/start-login"
export CONFIG_JSON="ci/plans/examples/rp-code-pkce-basic.config.json"
export ALIAS="greentic-rp"
# Optional: skip TLS verification for local self-signed suites
# export CS_SKIP_TLS_VERIFY=1
# Optional: rewrite localhost trigger URL for containers
# export HOST_REACHABLE_RP=1
```

## One-shot run

Kick off plan creation and execution in one command:

```bash
make conformance.full \
  CS_URL="$CS_URL" \
  CS_TOKEN="$CS_TOKEN" \
  RP_METADATA_URL="$RP_METADATA_URL" \
  RP_TRIGGER_URL="$RP_TRIGGER_URL" \
  CONFIG_JSON="$CONFIG_JSON" \
  ALIAS="$ALIAS"
```

The `conformance.full` target:

1. Normalises variant shorthands.
2. Merges your configuration JSON (alias, metadata URL) and creates or refreshes
   the plan in the suite.
3. Creates every module via the suite API and triggers your RP per test (fails
   fast on the first error by default).

`CONFIG_JSON` stays in the repo with placeholder values; the automation applies
runtime overrides so you do not need to edit the file manually.

Artifacts remain available through the suite UI; use `make conformance.reports`
to download JSON/HTML exports after the run.

## Variant shorthands

The automation understands the following helper values:

- `CLIENT_REG=dynamic` → `dynamic_client`
- `CLIENT_REG=static` → `static_client`
- `REQUEST_TYPE=plain_http_request | request_object | request_uri`

Overrides can be supplied via the environment:

```bash
CLIENT_REG=static make conformance.full ...
REQUEST_TYPE=request_object make conformance.full ...
```

## Troubleshooting

- **HTTP 401 on plan creation** – ensure `CS_TOKEN`/`SUITE_API_KEY` are exported
  in the current shell (reissue tokens if the suite volume was reset).
- **curl: (60) SSL certificate problem** – the suite uses a self-signed cert.
  Export `CS_SKIP_TLS_VERIFY=1` (or use `https://localhost:8443`) to allow
  unsigned certificates during local runs.
- **404 from `/api/plan/info/<plan>`** – ensure the plan slug exists by checking
  `curl -k -H "Authorization: Bearer $CS_TOKEN" "$CS_URL/api/plan/available"`.
  Use one of the listed `planName` values.
- **HTTP 500 “Illegal value for variant parameter client_registration”** – the
  suite rejected an unsupported value; rerun with `CLIENT_REG=dynamic_client` or
  `CLIENT_REG=static_client`, or run `make conformance.full` which performs a
  preflight check.
- **Plan creation failures referencing `client_registration`** – confirm your
  config JSON aliases match `ALIAS` and that `CLIENT_REG` maps to a listed
  variant in `/api/plan/info/<plan>`.
- **Plans stuck in `WAITING`** – ensure your RP trigger endpoint accepts the
  payload and begins an authorization request against the provided issuer.
  The stub harness (`python ci/docker/rp_app.py`) does not include this trigger,
  so wire `_conformance/start-login` into your RP before running `conformance.full`.
- **Suite cannot reach your RP (timeouts after module start)** – set
  `HOST_REACHABLE_RP=1` so `http://localhost:...` triggers are rewritten to
  `host.docker.internal` (macOS/Windows) or `172.17.0.1` (Linux). Alternatively,
  expose your RP on an address reachable from inside the suite container.
