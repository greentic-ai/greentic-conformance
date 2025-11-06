#!/usr/bin/env bash
set -euo pipefail

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  cat <<'USAGE'
Usage: run_conformance_plan.sh [PLAN_SLUG]

Drives an OpenID Foundation conformance plan using the suite API.

Environment variables:
  SUITE_BASE       Base URL for the conformance suite (default: https://localhost:8443)
  SUITE_API_KEY    API key generated in the suite UI (required)
  RP_BASE_URL      Base URL where the RP harness is exposed (default: http://localhost:8080)

The plan slug defaults to the PLAN environment variable when no argument is
provided. A successful run writes the plan identifier to reports/.last_plan_id.
USAGE
  exit 0
fi

PLAN="${1:-${PLAN:-}}"
SUITE_BASE="${SUITE_BASE:-${CS_URL:-https://localhost:8443}}"
RP_BASE_URL="${RP_BASE_URL:-http://localhost:8080}"

declare -A PLAN_ALIAS_MAP=(
  ["rp-code-pkce-basic"]="oidcc-client-basic-certification-test-plan"
  ["rp-fapi1-advanced"]="fapi1-advanced-final-client-test-plan"
  ["rp-fapi2-message-signing"]="fapi2-message-signing-id1-client-test-plan"
  ["rp-par-jar-dpop"]="fapi2-security-profile-id2-client-test-plan"
)

canonical_plan="${PLAN_ALIAS_MAP[$PLAN]:-$PLAN}"

declare -A PLAN_VARIANT_MAP=(
  ["rp-code-pkce-basic"]='{"request_type":"plain_http_request","client_registration":"dynamic_client"}'
  ["oidcc-client-basic-certification-test-plan"]='{"request_type":"plain_http_request","client_registration":"dynamic_client"}'
  ["rp-fapi1-advanced"]='{"fapi_profile":"plain_fapi","client_auth_type":"private_key_jwt","fapi_auth_request_method":"pushed","fapi_response_mode":"plain_response","fapi_client_type":"oidc"}'
  ["fapi1-advanced-final-client-test-plan"]='{"fapi_profile":"plain_fapi","client_auth_type":"private_key_jwt","fapi_auth_request_method":"pushed","fapi_response_mode":"plain_response","fapi_client_type":"oidc"}'
  ["rp-fapi2-message-signing"]='{"fapi_profile":"plain_fapi","client_auth_type":"private_key_jwt","fapi_auth_request_method":"pushed","fapi_response_mode":"jarm","fapi_client_type":"oidc"}'
  ["fapi2-message-signing-id1-client-test-plan"]='{"fapi_profile":"plain_fapi","client_auth_type":"private_key_jwt","fapi_auth_request_method":"pushed","fapi_response_mode":"jarm","fapi_client_type":"oidc"}'
  ["rp-par-jar-dpop"]='{"fapi_profile":"plain_fapi","client_auth_type":"private_key_jwt","fapi_auth_request_method":"pushed","fapi_response_mode":"jarm","fapi_client_type":"oidc","sender_constrained_tokens":"dpop"}'
  ["fapi2-security-profile-id2-client-test-plan"]='{"fapi_profile":"plain_fapi","client_auth_type":"private_key_jwt","fapi_auth_request_method":"pushed","fapi_response_mode":"jarm","fapi_client_type":"oidc","sender_constrained_tokens":"dpop"}'
)

if [[ -z "$PLAN" ]]; then
  echo "run_conformance_plan.sh: missing plan slug (argument or PLAN env)" >&2
  exit 2
fi

for bin in curl jq; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "run_conformance_plan.sh: missing required dependency '$bin'" >&2
    exit 2
  fi
done

auth_headers=()

SUITE_API_KEY="${SUITE_API_KEY:-${CS_TOKEN:-}}"

if [[ -z "${SUITE_API_KEY:-}" ]]; then
  echo "run_conformance_plan.sh: missing required SUITE_API_KEY/CS_TOKEN environment variable" >&2
  exit 2
fi

auth_headers+=(-H "Authorization: Bearer ${SUITE_API_KEY}")

suite_post() {
  local path=$1 body=$2
  curl --silent --show-error --insecure \
    -X POST "${SUITE_BASE}${path}" \
    "${auth_headers[@]}" \
    -H "Content-Type: application/json" \
    -d "$body" \
    -w '\n%{http_code}'
}

suite_get() {
  local path=$1
  curl --silent --show-error --insecure \
    "${SUITE_BASE}${path}" \
    "${auth_headers[@]}" \
    -w '\n%{http_code}'
}

redirect_uri="${RP_BASE_URL%/}/callback"

plan_name="${canonical_plan}"
plan_description="Automated run for ${PLAN} at $(date +%Y-%m-%dT%H:%M:%S)"

variant_json='null'
if [[ -n "${PLAN_VARIANT_MAP[$PLAN]:-}" ]]; then
  variant_json="${PLAN_VARIANT_MAP[$PLAN]}"
fi
if [[ "$variant_json" != "null" ]]; then
  variant_json=$(VARIANT_JSON="$variant_json" python3 - <<'PY'
import json
import os

raw = os.environ["VARIANT_JSON"]
data = json.loads(raw)
value = data.get("client_registration")
if value == "dynamic":
    data["client_registration"] = "dynamic_client"
elif value == "static":
    data["client_registration"] = "static_client"
print(json.dumps(data, separators=(",", ":")))
PY
)
fi
config_payload='{}'
if [[ -n "${PLAN_CONFIG_JSON:-}" ]]; then
  if [[ ! -f "$PLAN_CONFIG_JSON" ]]; then
    echo "run_conformance_plan.sh: PLAN_CONFIG_JSON path '$PLAN_CONFIG_JSON' not found" >&2
    exit 1
  fi
  config_payload=$(cat "$PLAN_CONFIG_JSON")
fi
payload=$(jq -n --arg description "$plan_description" --argjson cfg "$config_payload" '$cfg + {description: $description}')

echo "Creating plan '$plan_name' ($PLAN)..."

urlencode() {
  python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1]))' "$1"
}

plan_query="planName=$(urlencode "$plan_name")"
if [[ "$variant_json" != "null" ]]; then
  plan_query+="&variant=$(urlencode "$variant_json")"
fi

plan_raw=$(suite_post "/api/plan?${plan_query}" "$payload") || true
http_code=$(tail -n1 <<<"$plan_raw")
plan_response=$(head -n -1 <<<"$plan_raw")

if [[ "$http_code" -ge 400 && "$variant_json" != "null" && "$plan_response" == *"has been set by user"* ]]; then
  echo "Server rejected variant overrides for ${PLAN}; retrying without custom variant..."
  variant_json='null'
  plan_query="planName=$(urlencode "$plan_name")"
  plan_raw=$(suite_post "/api/plan?${plan_query}" "$payload") || true
  http_code=$(tail -n1 <<<"$plan_raw")
  plan_response=$(head -n -1 <<<"$plan_raw")
fi

if [[ "$http_code" -ge 400 || -z "$plan_response" ]]; then
  echo "run_conformance_plan.sh: plan creation failed (HTTP ${http_code}). Response:" >&2
  echo "$plan_response" >&2
  exit 1
fi
plan_id=$(jq -r '._id // .id // .planId // empty' <<<"$plan_response")

if [[ -z "$plan_id" ]]; then
  echo "run_conformance_plan.sh: failed to create plan. Response:" >&2
  echo "$plan_response" >&2
  exit 1
fi

echo "Plan created: $plan_id"

echo "Starting plan..."
suite_post "/api/plan/${plan_id}/start" '{}' > /dev/null

echo "Polling plan status..."
status="UNKNOWN"
reports_dir="reports"
mkdir -p "$reports_dir"
plan_json_path="${reports_dir}/plan-${plan_id}.json"

if [[ "${RUN_CONFORMANCE_PLAN_NO_WAIT:-}" == "1" ]]; then
  plan_raw=$(suite_get "/api/plan/${plan_id}") || true
  http_code=$(tail -n1 <<<"$plan_raw")
  plan_json=$(head -n -1 <<<"$plan_raw")
  if [[ "$http_code" -ge 400 || -z "$plan_json" ]]; then
    echo "run_conformance_plan.sh: initial fetch failed (HTTP ${http_code}). Response:" >&2
    echo "$plan_json" >&2
    exit 1
  fi
  jq '.' <<<"$plan_json" > "$plan_json_path"
  echo "$plan_id" > "${reports_dir}/.last_plan_id"
  echo "Plan ${plan_id} created (no-wait mode)."
  exit 0
fi

while true; do
  sleep 5
  plan_raw=$(suite_get "/api/plan/${plan_id}") || true
  http_code=$(tail -n1 <<<"$plan_raw")
  plan_json=$(head -n -1 <<<"$plan_raw")

  if [[ "$http_code" -ge 400 || -z "$plan_json" ]]; then
    echo "run_conformance_plan.sh: polling failed (HTTP ${http_code}). Response:" >&2
    echo "$plan_json" >&2
    exit 1
  fi

  status=$(jq -r '.status // .planStatus // "UNKNOWN"' <<<"$plan_json")
  echo "  status=${status}"

  if [[ "$status" == "FINISHED" || "$status" == "FINISHED_WITH_ERRORS" || "$status" == "FAILED" ]]; then
    jq '.' <<<"$plan_json" > "$plan_json_path"
    break
  fi
done

failures=$(jq '[.modules[]? | select((.result // .status) != "PASSED")] | length' "$plan_json_path")

echo "$plan_id" > "${reports_dir}/.last_plan_id"

if [[ "$failures" -gt 0 || "$status" != "FINISHED" ]]; then
  echo "Plan ${plan_id} completed with ${failures} failing module(s)" >&2
  exit 1
fi

echo "Plan ${plan_id} finished successfully."
exit 0
