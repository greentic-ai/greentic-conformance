#!/usr/bin/env bash
set -euo pipefail

: "${CS_URL:?missing CS_URL (suite base URL)}"
: "${CS_TOKEN:?missing CS_TOKEN (suite API token)}"
: "${PLAN:?missing PLAN (suite plan name)}"
: "${ALIAS:?missing ALIAS (RP alias)}"
: "${CONFIG_JSON:?missing CONFIG_JSON (plan configuration JSON)}"
: "${RP_METADATA_URL:?missing RP_METADATA_URL (RP metadata URL)}"

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

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

for cmd in curl jq python3; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required command: $cmd" >&2
    exit 1
  fi
done

RUNNER_DIR="${ROOT}/third_party/oidf-conformance/runner"
RUNNER="${RUNNER_DIR}/run-test-plan.py"
mkdir -p "$RUNNER_DIR"
if [[ ! -f "$RUNNER" ]]; then
  echo "[auto] fetching OIDF runner..."
  curl -fsSL "https://raw.githubusercontent.com/openid-certification/conformance-suite/master/scripts/run-test-plan.py" -o "$RUNNER"
  chmod +x "$RUNNER"
fi

echo "[auto] preflight variants..."
VARIANT_INFO=$(curl -fsS -H "Authorization: Bearer ${CS_TOKEN}" "${CS_URL}/api/info/plan/${PLAN}")
echo "$VARIANT_INFO" | jq -e --arg value "$CLIENT_REG" '
  .variantInfo.client_registration.values[] | select(. == $value)
' > /dev/null || {
  echo "Invalid client_registration: ${CLIENT_REG}" >&2
  echo "Allowed: $(echo "$VARIANT_INFO" | jq -r '.variantInfo.client_registration.values | join(", ")')" >&2
  exit 1
}

echo "[auto] creating plan: ${PLAN}"
"${ROOT}/ci/scripts/run_conformance_plan.sh" "$PLAN"

echo "[auto] running all modules for plan: ${PLAN}"
fail_args=()
if [[ "$FAIL_FAST" == "true" ]]; then
  fail_args+=(--fail-fast)
fi
python3 "$RUNNER" \
  --server "$CS_URL" \
  --token "$CS_TOKEN" \
  --plan "$PLAN" \
  --alias "$ALIAS" \
  --request-type "$REQUEST_TYPE" \
  --client-registration "$CLIENT_REG" \
  --config "$CONFIG_JSON" \
  --rp-metadata "$RP_METADATA_URL" \
  --run-all \
  "${fail_args[@]}"

echo "[auto] complete."
