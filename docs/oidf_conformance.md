# OIDF Conformance (Hosted Suite)

Run OpenID Foundation RP conformance plans against the hosted suite at
`https://www.certification.openid.net` with a single command. The tooling
supports two modes:

- **Local development** – automatically spins up a Cloudflare Quick Tunnel so a
  localhost RP is reachable by the hosted suite.
- **CI / staging** – skips the tunnel and points at a pre-existing public HTTPS
  deployment.

## Prerequisites

- Hosted suite account with an API token (Profile → **API Token**).
- `jq` and `curl` in your shell.
- [`cloudflared`](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/install-and-setup/installation/)
  when running locally with `USE_TUNNEL=1`.
- An RP that exposes the required endpoints:
  - `/_conformance/start-login` – starts the OIDC login for a given module.
  - `/_conformance/callback` – receives the authorization response.

## Environment configuration

Copy the sample file and fill in the hosted values:

```bash
cp ci/env/conformance.hosted.example.env ci/env/conformance.hosted.env
# edit ci/env/conformance.hosted.env (CS_TOKEN, optional RP_BASE, etc.)
```

Important fields:

| Variable        | Description                                                     |
| --------------- | --------------------------------------------------------------- |
| `CS_URL`        | Hosted suite URL (leave as `https://www.certification.openid.net`). |
| `CS_TOKEN`      | API token from the hosted UI.                                   |
| `PLAN_ID`       | Identifier of the hosted plan (create it in the UI first).      |
| `CONFIG_JSON`   | Base RP configuration (updated at runtime with alias & URLs).   |
| `USE_TUNNEL`    | `1` (default) starts a Cloudflare tunnel; set to `0` in CI.     |
| `RP_LOCAL_URL`  | Local RP base when tunnelling (default: `http://localhost:8080`). |
| `RP_BASE`       | Public RP base URL (set when `USE_TUNNEL=0`).                   |

All variables in `.env` or `ci/env/conformance.hosted.env` are automatically
exported by the `Makefile`.

## Local development (Quick Tunnel)

With `USE_TUNNEL=1` (default), run:

```bash
make conformance.plan
```

The automation:

1. Starts a Cloudflare Quick Tunnel pointing at `RP_LOCAL_URL`.
2. Patches the RP configuration (redirect URI + trigger URL).
3. Validates the hosted plan (`PLAN_ID`) exists and starts it if idle.
4. Creates and starts each module.

Monitor progress at the printed URL, e.g.
`https://www.certification.openid.net/plan-detail.html?plan=<PLAN_ID>`.

The tunnel is torn down automatically when the command finishes.

## CI / staging (no tunnel)

Deploy the RP at a public HTTPS URL and set:

```bash
USE_TUNNEL=0 RP_BASE=https://rp-staging.example.com make conformance.plan
```

### GitHub Actions

Use `.github/workflows/conformance-hosted.yml` to trigger a hosted run without a
tunnel:

1. Add `CS_TOKEN` to repository secrets.
2. Dispatch the workflow with `rp_base=https://rp-staging.example.com plan_id=<PLAN_ID_FROM_UI>`.

## Troubleshooting

- **401/403** – regenerate the hosted suite API token and update `CS_TOKEN`.
- **400 on module create** – the hosted suite returns a JSON payload describing
  the missing/invalid field (common issues: redirect URI mismatch, missing JWKS,
  missing `openid` scope). Fix the config and rerun.
- **Hosted suite cannot reach your RP** – ensure the RP is reachable via public
  HTTPS. For local testing, keep `USE_TUNNEL=1`; for CI, double-check firewalls
  and certificates.
- **Unknown plan id** – ensure `PLAN_ID` matches an existing plan that belongs
  to the API token’s account (viewable in the hosted UI).
- **Modules remain “Not run”** – open the printed plan URL to watch module
  status and review logs.
