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
```

## One-shot run

Kick off plan creation and execution in one command:

```bash
make conformance.full \
  CS_URL="$CS_URL" \
  CS_TOKEN="$CS_TOKEN" \
  RP_METADATA_URL="$RP_METADATA_URL"
```

The `conformance.full` target:

1. Normalises variant shorthands.
2. Creates or refreshes the plan in the suite.
3. Fetches the upstream runner script if needed.
4. Executes every module headlessly (fails fast on the first error by default).

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
- **HTTP 500 “Illegal value for variant parameter client_registration”** – the
  suite rejected an unsupported value; rerun with `CLIENT_REG=dynamic_client` or
  `CLIENT_REG=static_client`, or run `make conformance.full` which performs a
  preflight check.
- **Plans stuck in `WAITING`** – the suite cannot reach your RP. Start the stub
  harness (`python ci/docker/rp_app.py`) or expose your RP publicly and update
  `RP_METADATA_URL`.
