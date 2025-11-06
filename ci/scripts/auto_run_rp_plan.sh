#!/usr/bin/env bash
set -euo pipefail

: "${CS_URL:?missing CS_URL (suite base URL)}"
: "${CS_TOKEN:?missing CS_TOKEN (suite API token)}"
: "${ALIAS:?missing ALIAS (suite RP alias)}"
: "${CONFIG_JSON:?missing CONFIG_JSON (plan configuration JSON)}"
: "${RP_METADATA_URL:?missing RP_METADATA_URL (RP metadata URL)}"
: "${RP_TRIGGER_URL:?missing RP_TRIGGER_URL (RP trigger endpoint)}"

PLAN="${PLAN:-oidcc-client-basic-certification-test-plan}"
CLIENT_REG="${CLIENT_REG:-dynamic_client}"
REQUEST_TYPE="${REQUEST_TYPE:-plain_http_request}"
FAIL_FAST="${FAIL_FAST:-true}"

case "$CLIENT_REG" in
  dynamic) CLIENT_REG="dynamic_client" ;;
  static) CLIENT_REG="static_client" ;;
  dynamic_client|static_client) ;;
  *)
    echo "Unsupported CLIENT_REG value: ${CLIENT_REG}" >&2
    exit 1
    ;;
esac

case "$REQUEST_TYPE" in
  plain_http_request|request_object|request_uri) ;;
  *)
    echo "Unsupported REQUEST_TYPE value: ${REQUEST_TYPE}" >&2
    exit 1
    ;;
esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

for cmd in curl jq python3; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required command: $cmd" >&2
    exit 1
  fi
done

curl_opts=()
rp_modules_flags=()
suite_insecure=0
case "${CS_URL}" in
  https://localhost|https://localhost:*|https://127.*)
    curl_opts+=(--insecure)
    rp_modules_flags+=(--insecure)
    suite_insecure=1
    ;;
esac
if [[ "${CS_SKIP_TLS_VERIFY:-}" == "1" ]]; then
  curl_opts+=(--insecure)
  rp_modules_flags+=(--insecure)
  suite_insecure=1
fi

if [[ "$suite_insecure" -eq 1 ]]; then
rp_modules_flags=(--insecure)
else
  rp_modules_flags=()
fi

TEMP_CONFIG=""
cleanup() {
  [[ -n "$TEMP_CONFIG" && -f "$TEMP_CONFIG" ]] && rm -f "$TEMP_CONFIG"
}
trap cleanup EXIT

if [[ -n "${CONFIG_JSON:-}" && -f "${CONFIG_JSON}" ]]; then
  CONFIG_ALIAS=$(jq -r '.alias // empty' "$CONFIG_JSON" 2>/dev/null || echo "")
  if [[ -n "$CONFIG_ALIAS" && "$CONFIG_ALIAS" != "$ALIAS" ]]; then
    echo "Config alias mismatch: expected '$ALIAS' but found '$CONFIG_ALIAS' in ${CONFIG_JSON}" >&2
    exit 1
  fi
  TEMP_CONFIG="$(mktemp)"
  jq --arg alias "$ALIAS" --arg url "$RP_METADATA_URL" '
    .alias = $alias
    | .rp_metadata_url = $url
  ' "$CONFIG_JSON" > "$TEMP_CONFIG"
  export PLAN_CONFIG_JSON="$TEMP_CONFIG"
fi

fail_fast_flag=()
if [[ "$FAIL_FAST" == "true" ]]; then
  fail_fast_flag=(--fail-fast)
fi

echo "[auto] preflight variants for ${PLAN}"
VARIANT_INFO=$(curl "${curl_opts[@]}" -fsS -H "Authorization: Bearer ${CS_TOKEN}" "${CS_URL%/}/api/plan/info/${PLAN}")
if [[ "$(echo "$VARIANT_INFO" | jq -r '.variants.client_registration.variantValues | type?')" != "object" ]]; then
  echo "Plan ${PLAN} does not expose client_registration variant details" >&2
  exit 1
fi
if ! echo "$VARIANT_INFO" | jq -e --arg v "$CLIENT_REG" '(.variants.client_registration.variantValues // {}) | has($v)' >/dev/null; then
  echo "Invalid client_registration=${CLIENT_REG}" >&2
  echo "Allowed: $(echo "$VARIANT_INFO" | jq -r '.variants.client_registration.variantValues | keys | join(", ")')" >&2
  exit 1
fi
if [[ "$(echo "$VARIANT_INFO" | jq -r '.variants.request_type.variantValues | type?')" != "object" ]]; then
  echo "Plan ${PLAN} does not expose request_type variant details" >&2
  exit 1
fi
if ! echo "$VARIANT_INFO" | jq -e --arg v "$REQUEST_TYPE" '(.variants.request_type.variantValues // {}) | has($v)' >/dev/null; then
  echo "Invalid request_type=${REQUEST_TYPE}" >&2
  echo "Allowed: $(echo "$VARIANT_INFO" | jq -r '.variants.request_type.variantValues | keys | join(", ")')" >&2
  exit 1
fi

echo "[auto] creating plan: ${PLAN}"
PLAN_ARG="${PLAN}"
RUN_CONFORMANCE_PLAN_NO_WAIT=1 "${ROOT}/ci/scripts/run_conformance_plan.sh" "$PLAN_ARG"
unset PLAN_CONFIG_JSON

PLAN_FILE="${ROOT}/reports/.last_plan_id"
if [[ ! -f "$PLAN_FILE" ]]; then
  echo "Plan id file not found at ${PLAN_FILE}" >&2
  exit 1
fi
PLAN_ID="$(<"$PLAN_FILE")"
PLAN_ID="${PLAN_ID//[$'\r\n']/}"
if [[ -z "$PLAN_ID" ]]; then
  echo "Plan id in ${PLAN_FILE} is empty" >&2
  exit 1
fi

echo "[auto] creating modules for plan ${PLAN_ID}..."
PLAN_DETAIL=$(curl "${curl_opts[@]}" -fsS -H "Authorization: Bearer ${CS_TOKEN}" "${CS_URL%/}/api/plan/${PLAN_ID}")
if [[ -z "$PLAN_DETAIL" ]]; then
  echo "Failed to retrieve plan detail for ${PLAN_ID}" >&2
  exit 1
fi

MODULE_COUNT=$(echo "$PLAN_DETAIL" | jq '.modules | length')
if [[ "$MODULE_COUNT" -eq 0 ]]; then
  echo "Plan ${PLAN_ID} contains no modules; aborting." >&2
  exit 1
fi

urlencode() {
  python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))' "$1"
}

while IFS= read -r module; do
  test_name=$(echo "$module" | jq -r '.testModule')
  variant_json=$(echo "$module" | jq -c '.variant // {}')
  params="test=$(urlencode "$test_name")&plan=${PLAN_ID}"
  if [[ "$variant_json" != "{}" ]]; then
    params+="&variant=$(urlencode "$variant_json")"
  fi
  response=$(curl "${curl_opts[@]}" --silent --show-error -X POST "${CS_URL%/}/api/runner?${params}" \
    -H "Authorization: Bearer ${CS_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{}' -w '\n%{http_code}')
  http_code=$(tail -n1 <<<"$response")
  body=$(head -n -1 <<<"$response")
  if [[ "$http_code" -ge 400 || -z "$body" ]]; then
    echo "Failed to create module for ${test_name} (HTTP ${http_code})" >&2
    echo "$body" >&2
    exit 1
  fi
  module_id=$(echo "$body" | jq -r '._id // .id // .moduleId // .testId // empty')
  echo "[auto] module created: ${test_name} -> ${module_id}"
done < <(echo "$PLAN_DETAIL" | jq -c '.modules[]')

echo "[auto] driving RP modules (plan ${PLAN_ID})..."
python3 "${ROOT}/ci/tools/run_rp_modules.py" \
  --server "${CS_URL}" \
  --token "${CS_TOKEN}" \
  --alias "${ALIAS}" \
  --plan-id "${PLAN_ID}" \
  --trigger "${RP_TRIGGER_URL}" \
  "${rp_modules_flags[@]}" \
  "${fail_fast_flag[@]}"
