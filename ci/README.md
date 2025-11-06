# Conformance Orchestration

This folder contains the plumbing required to run the OpenID Foundation
conformance suite alongside the Greentic RP harness stub. The workflow is:

1. Launch the suite and RP containers:

   ```sh
   docker compose -f ci/docker/compose.conformance.yml up -d --wait
   ```

2. Run the desired RP plan (the example below drives the basic RP Code+PKCE
   variant). An API key must be generated in the suite UI and exported as
   `SUITE_API_KEY` before running the script.

   ```sh
   export SUITE_API_KEY=xxxxxxxxxxxxxxxx
   ./ci/scripts/run_conformance_plan.sh rp-code-pkce-basic
   ```

3. Collect the reports for the last run into `reports/`:

   ```sh
   ./ci/scripts/collect_reports.sh
   ```

4. Tear everything down when finished:

   ```sh
   docker compose -f ci/docker/compose.conformance.yml down
   ```

## Configuration

- `SUITE_BASE` (default: `https://localhost:8443`) – base URL exposed by the
  conformance suite. Update this if the compose stack is bound to a different
  host or port.
- `RP_BASE_URL` (default: `http://localhost:8080`) – external URL for the RP
  harness stub. The `run_conformance_plan.sh` script uses this to populate the
  redirect URI sent to the suite.
- `SUITE_API_KEY` – API key generated under *Account → API Keys* within the
  suite UI. Required by both automation scripts.
- `CONFIG_JSON` – RP configuration template passed to the suite. It must include
  the relying party alias, redirect URI(s), scopes (at minimum `openid`),
  metadata URL, and any additional plan-specific fields your module requires
  (e.g. JWKS/JWKS URI for `private_key_jwt`).
- `RP_TRIGGER_URL` – HTTP endpoint in your RP that starts the login flow for a
  module. When running the suite in Docker, ensure this URL is reachable from
  inside the container (use `host.docker.internal` on macOS/Windows or
  `172.17.0.1` on Linux, or set `HOST_REACHABLE_RP=1` so the automation rewrites
  `http://localhost` accordingly).

The automation stores the last executed plan identifier in
`reports/.last_plan_id` and keeps a JSON snapshot of the plan response for
reference.
