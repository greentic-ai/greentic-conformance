#!/usr/bin/env bash
set -euo pipefail

: "${CS_URL:?missing CS_URL}"                  # Hosted suite URL
: "${CS_TOKEN:?missing CS_TOKEN}"              # API token from hosted UI
: "${PLAN:?missing PLAN}"                      # e.g. oidcc-client-basic-certification-test-plan
: "${ALIAS:?missing ALIAS}"                    # RP alias
: "${CLIENT_REG:?missing CLIENT_REG}"          # dynamic_client / static_client
: "${REQUEST_TYPE:?missing REQUEST_TYPE}"      # plain_http_request / request_object / request_uri
: "${CONFIG_JSON:?missing CONFIG_JSON}"        # Base RP config JSON

: "${USE_TUNNEL:=1}"
: "${RP_LOCAL_URL:=http://localhost:8080}"
: "${RP_BASE:=}"

TUNNEL_ENV=".cf-tunnel.env"
TMP_CFG="$(mktemp -t rp_cfg_XXXX.json)"
trap 'rm -f "${TMP_CFG}" "${TUNNEL_ENV}" 2>/dev/null || true' EXIT

auth_header() {
  printf 'Authorization: Bearer %s' "$CS_TOKEN"
}

api() {
  local method=$1
  local path=$2
  local body="${3:-}"
  local url="${CS_URL%/}${path}"
  local args=(-sS -X "$method" -H "$(auth_header)")
  if [[ -n "$body" ]]; then
    args+=(-H 'Content-Type: application/json' -d "$body")
  fi
  args+=("$url" -w '\n%{http_code}')

  local resp
  resp=$(curl "${args[@]}")
  local http_code="${resp##*$'\n'}"
  local payload="${resp%$'\n'*}"
  if ! [[ "$http_code" =~ ^[0-9]+$ ]] || (( http_code < 200 || http_code >= 300 )); then
    echo "[api] ${method} ${path} -> HTTP ${http_code}" >&2
    case "$http_code" in
      401)
        echo "[api] The hosted suite rejected the bearer token. Refresh CS_TOKEN from https://www.certification.openid.net (Profile → API Token)." >&2
        ;;
      403)
        echo "[api] Access denied. Ensure your account has access to the requested plan and that CS_TOKEN has the correct scope." >&2
        ;;
      404)
        echo "[api] Endpoint not found. Double-check CS_URL ('${CS_URL}') and verify the plan slug '${PLAN}' exists. This response is also returned when the API token lacks access to the runner API." >&2
        ;;
      000)
        echo "[api] Network failure; confirm internet connectivity and that the host '${CS_URL}' resolves from this environment." >&2
        ;;
    esac
    if jq -e . >/dev/null 2>&1 <<<"$payload"; then
      echo "$payload" | jq .
    else
      echo "$payload"
    fi
    exit 1
  fi
  printf '%s' "$payload"
}

if [[ "$USE_TUNNEL" == "1" && -z "$RP_BASE" ]]; then
  RP_LOCAL_URL="${RP_LOCAL_URL}" bash ci/scripts/cf_tunnel.sh
  # shellcheck disable=SC1090
  source "${TUNNEL_ENV}"
  echo "[conf] using Cloudflare tunnel (${RP_BASE})"
else
  : "${RP_BASE:?RP_BASE must be set when USE_TUNNEL=0}"
fi

case "$RP_BASE" in
  https://*) ;;
  *)
    echo "[conf] RP_BASE must be https (hosted suite requirement)"
    exit 1
    ;;
esac

RP_TRIGGER_URL="${RP_BASE}/_conformance/start-login"
REDIRECT_URI="${RP_BASE}/_conformance/callback"
echo "[conf] RP_BASE=${RP_BASE}"
echo "[conf] RP_TRIGGER_URL=${RP_TRIGGER_URL}"
echo "[conf] REDIRECT_URI=${REDIRECT_URI}"

jq --arg redirect "${REDIRECT_URI}" '.client.redirect_uri = $redirect' \
  "$CONFIG_JSON" > "${TMP_CFG}"

# --- Create or validate PLAN_ID on the hosted suite ---
create_plan() {
  local plan_name="$1"
  local payload
  payload=$(jq -nc --arg plan "$plan_name" '{planName:$plan}')

  local response
  response=$(api POST "/api/runner/plan" "$payload")
  PLAN_ID=$(echo "$response" | jq -r '.id // .planId // empty')
  if [[ -z "$PLAN_ID" ]]; then
    echo "[conf] failed to obtain plan id from response" >&2
    exit 1
  fi
  echo "[conf] plan created: ${PLAN_ID}"

  api POST "/api/runner/plan/${PLAN_ID}/start" > /dev/null
  echo "[conf] plan started"
}

validate_or_create_plan() {
  if [[ -n "${PLAN_ID:-}" ]]; then
    local code
    code=$(curl -sS -H "$(auth_header)" \
      "${CS_URL%/}/api/runner/plan/${PLAN_ID}" -o /dev/null -w '%{http_code}')
    if [[ "$code" == "200" ]]; then
      echo "[conf] using existing PLAN_ID=${PLAN_ID}"
      return 0
    fi
    echo "[conf] Provided PLAN_ID not usable on hosted (http=${code}); creating a new one."
    unset PLAN_ID
  fi
  create_plan "${PLAN}"
}

validate_or_create_plan

module_payload=$(jq -nc \
  --arg alias "$ALIAS" \
  --arg request_type "$REQUEST_TYPE" \
  --arg client_registration "$CLIENT_REG" \
  --arg trigger "$RP_TRIGGER_URL" \
  --argjson cfg "$(cat "${TMP_CFG}")" \
'{
   alias: $alias,
   config: ($cfg + { rp_trigger_url: $trigger, alias: $alias }),
   variant: { request_type: $request_type, client_registration: $client_registration }
 }')

module_resp=$(curl -sS -H "$(auth_header)" -H "Content-Type: application/json" \
  -d "${module_payload}" "${CS_URL%/}/api/runner/plan/${PLAN_ID}/module" -w '\n%{http_code}')
module_code="${module_resp##*$'\n'}"
module_body="${module_resp%$'\n'*}"
if ! [[ "$module_code" =~ ^(200|201)$ ]]; then
  echo "[conf] module creation failed (HTTP ${module_code}):" >&2
  if jq -e . >/dev/null 2>&1 <<<"$module_body"; then
    echo "$module_body" | jq -r '"error: " + ((.error // .code // .status // "-")|tostring) + "\nmessage: " + ((.message // .error_description // .detail // "-")|tostring)'
  else
    echo "$module_body"
  fi
  exit 1
fi

MODULE_ID=$(echo "$module_body" | jq -r '.id // .moduleId // empty')
if [[ -z "$MODULE_ID" ]]; then
  echo "[conf] missing module id in response" >&2
  exit 1
fi
echo "[conf] module created: ${MODULE_ID}"

start_code=$(curl -sS -H "$(auth_header)" -X POST \
  "${CS_URL%/}/api/runner/plan/${PLAN_ID}/module/${MODULE_ID}/start" -w '%{http_code}')
if ! [[ "$start_code" =~ ^(200|204)$ ]]; then
  echo "[conf] module start failed (HTTP ${start_code})" >&2
  exit 1
fi
echo "[conf] module started"
echo "[conf] Monitor: ${CS_URL%/}/plan-detail.html?plan=${PLAN_ID}"
