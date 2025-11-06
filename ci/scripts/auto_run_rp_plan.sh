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

EFFECTIVE_RP_TRIGGER_URL="$RP_TRIGGER_URL"
if [[ "${HOST_REACHABLE_RP:-0}" == "1" ]]; then
  if [[ "$RP_TRIGGER_URL" =~ ^(https?)://([^/]+)(/.*)?$ ]]; then
    _proto="${BASH_REMATCH[1]}"
    _hostport="${BASH_REMATCH[2]}"
    _path="${BASH_REMATCH[3]}"
    [[ -z "$_path" ]] && _path="/"
    _host="${_hostport%%:*}"
    _port="${_hostport#*:}"
    [[ "$_port" == "$_hostport" ]] && _port=""
    if [[ "$_host" == "localhost" || "$_host" == "127.0.0.1" ]]; then
      case "$(uname -s)" in
        Darwin|Windows_NT)
          _mapped_host="host.docker.internal"
          ;;
        *)
          _mapped_host="${DOCKER_HOST_IP:-172.17.0.1}"
          ;;
      esac
      [[ -n "$_port" && "$_port" != "$_hostport" ]] && _mapped_host="${_mapped_host}:${_port}"
      EFFECTIVE_RP_TRIGGER_URL="${_proto}://${_mapped_host}${_path}"
      echo "[auto] rewriting RP trigger URL to ${EFFECTIVE_RP_TRIGGER_URL}"
    fi
  fi
fi

auth_hdr() {
  printf "Authorization: Bearer %s" "$CS_TOKEN"
}

curl_api() {
  local method=$1
  local path=$2
  local body="${3:-}"
  local url="${CS_URL%/}${path}"
  local cmd=(curl -sS)
  if ((${#curl_opts[@]})); then
    cmd+=("${curl_opts[@]}")
  fi
  cmd+=(-X "$method" -H "$(auth_hdr)")
  if [[ -n "$body" ]]; then
    cmd+=(-H "Content-Type: application/json" -d "$body")
  fi
  cmd+=("$url" -w '\n%{http_code}')
  set +e
  local resp
  resp=$("${cmd[@]}")
  local curl_status=$?
  set -e
  if ((curl_status != 0)); then
    echo "[api] curl failed (${curl_status}) for ${method} ${path}" >&2
    exit 1
  fi
  local http_code="${resp##*$'\n'}"
  local payload="${resp%$'\n'*}"
  if ! [[ "$http_code" =~ ^[0-9]+$ ]] || (( http_code < 200 || http_code >= 300 )); then
    echo "[api] ${method} ${path} -> HTTP ${http_code}" >&2
    [[ -n "$payload" ]] && echo "$payload" >&2
    exit 1
  fi
  printf '%s' "$payload"
}

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
VARIANT_INFO=$(curl_api GET "/api/plan/info/${PLAN}")
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

echo "[auto] polling plan readiness..."
plan_ready=0
status_json=""
for _ in {1..15}; do
  status_json=$(curl_api GET "/api/plan/${PLAN_ID}")
  plan_status=$(echo "$status_json" | jq -r '.status // .planStatus // "UNKNOWN"')
  echo "  status=${plan_status}"
  case "$plan_status" in
    FAILED|STOPPED)
      echo "[auto] plan ${PLAN_ID} entered terminal state (${plan_status})" >&2
      echo "$status_json"
      exit 1
      ;;
    WAITING|CONFIGURED|RUNNING)
      plan_ready=1
      break
      ;;
  esac
  sleep 1
done

if [[ "$plan_ready" -ne 1 ]]; then
  echo "[auto] proceeding with module creation despite status=${plan_status}"
fi

echo "[auto] creating modules for plan ${PLAN_ID}..."
PLAN_DETAIL=$(curl_api GET "/api/plan/${PLAN_ID}")
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
  module_body=""
  module_id=""
  for attempt in {1..10}; do
    set +e
    resp=$(curl -sS "${curl_opts[@]}" -X POST "${CS_URL%/}/api/runner?${params}" \
      -H "$(auth_hdr)" \
      -H "Content-Type: application/json" \
      -d '{}' -w '\n%{http_code}')
    curl_status=$?
    set -e
    if (( curl_status != 0 )); then
      echo "[auto] curl error creating module ${test_name} (attempt ${attempt})" >&2
      echo "$resp" >&2
      if (( attempt == 10 )); then
        exit 1
      fi
      sleep 1
      continue
    fi
    http_code="${resp##*$'\n'}"
    module_body="${resp%$'\n'*}"
    if [[ "$http_code" == "200" || "$http_code" == "201" ]]; then
      module_id=$(echo "$module_body" | jq -r '._id // .id // .moduleId // .testId // empty')
      [[ -n "$module_id" ]] && break
    fi
    if [[ "$http_code" == "400" && "$attempt" -lt 10 ]]; then
      echo "[auto] module create attempt ${attempt} returned 400; retrying..."
      sleep 1
      continue
    fi
    echo "[auto] failed to create module ${test_name} (HTTP ${http_code})" >&2
    [[ -n "$module_body" ]] && echo "$module_body" >&2
    exit 1
  done

  if [[ -z "$module_id" ]]; then
    echo "[auto] module id missing for ${test_name}" >&2
    exit 1
  fi

  echo "[auto] module created: ${test_name} -> ${module_id}"
  echo "[auto] starting module ${module_id}..."
  curl_api POST "/api/runner/${module_id}" '{}'
done < <(echo "$PLAN_DETAIL" | jq -c '.modules[]')

echo "[auto] driving RP modules (plan ${PLAN_ID})..."
python3 "${ROOT}/ci/tools/run_rp_modules.py" \
  --server "${CS_URL}" \
  --token "${CS_TOKEN}" \
  --alias "${ALIAS}" \
  --plan-id "${PLAN_ID}" \
  --trigger "${EFFECTIVE_RP_TRIGGER_URL}" \
  "${rp_modules_flags[@]}" \
  "${fail_fast_flag[@]}"
