# Hosted Conformance Workflow

This folder contains the glue scripts used to exercise the hosted OpenID
Foundation conformance suite (`https://www.certification.openid.net`) against a
Greentic RP.

## Quick start

1. Generate an API token in the hosted UI (Profile → **API Token**).
2. Copy `ci/env/conformance.hosted.example.env` to `ci/env/conformance.hosted.env`
   and fill in the values (`CS_TOKEN`, optional `RP_BASE`, etc.).
3. Ensure your RP exposes:
   - `/_conformance/start-login` – kicks off the hosted login flow.
   - `/_conformance/callback` – receives the authorization response.
4. Run the plan:

   ```bash
   make conformance.plan
   ```

By default the command spins up a Cloudflare Quick Tunnel so a local RP is
reachable. Set `USE_TUNNEL=0` and provide a public `RP_BASE` when running in
CI/staging.

## Scripts

- `ci/scripts/cf_tunnel.sh` – starts a Cloudflare Quick Tunnel and writes the
  generated URL to `.cf-tunnel.env`.
- `ci/scripts/run_conformance_hosted_with_tunnel.sh` – orchestrates the end to
  end flow: optional tunnel, config patching, plan/module creation, and module
  start.

The main `Makefile` target `conformance.plan` wires these together.

## CI workflow

`.github/workflows/conformance-hosted.yml` demonstrates how to run the hosted
plan without a tunnel. Provide `CS_TOKEN` as a GitHub secret and dispatch the
workflow with a public `rp_base` value.
