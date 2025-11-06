#!/usr/bin/env bash
set -euo pipefail

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  cat <<'USAGE'
Usage: collect_reports.sh [PLAN_ID]

Downloads JSON and HTML reports for the most recent conformance plan run.

Environment variables:
  SUITE_BASE       Base URL for the conformance suite (default: https://localhost:8443)
  SUITE_API_KEY    API key generated in the suite UI (required)

When PLAN_ID is omitted the script reads reports/.last_plan_id.
USAGE
  exit 0
fi

SUITE_BASE="${SUITE_BASE:-https://localhost:8443}"
SUITE_API_KEY="${SUITE_API_KEY:-}"
PLAN_ID="${1:-}"

mkdir -p reports
if [[ -z "$PLAN_ID" ]]; then
  if [[ -f reports/.last_plan_id ]]; then
    PLAN_ID=$(<reports/.last_plan_id)
  else
    echo "collect_reports.sh: no plan identifier available; nothing to collect" >&2
    exit 0
  fi
fi

plan_json_path="reports/plan-${PLAN_ID}.json"
if [[ ! -f "$plan_json_path" ]]; then
  echo "collect_reports.sh: plan snapshot ${plan_json_path} missing; skipping collection" >&2
  exit 0
fi

for bin in curl jq; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "collect_reports.sh: missing required dependency '$bin'" >&2
    exit 2
  fi
done

auth_headers=()
if [[ -n "$SUITE_API_KEY" ]]; then
  auth_headers+=(-H "Authorization: Bearer ${SUITE_API_KEY}")
else
  echo "collect_reports.sh: SUITE_API_KEY not set; attempting downloads without auth header" >&2
fi

suite_get_raw() {
  local path=$1
  curl --silent --show-error --fail --insecure \
    "${SUITE_BASE}${path}" \
    "${auth_headers[@]}"
}

output_dir="reports/${PLAN_ID}"
mkdir -p "$output_dir"

echo "Collecting reports for plan ${PLAN_ID} into ${output_dir}"

download_asset() {
  local path=$1
  local output=$2
  if data=$(suite_get_raw "$path" 2>/dev/null); then
    printf "%s" "$data" > "$output"
    return 0
  fi
  return 1
}

if download_asset "/api/plan/${PLAN_ID}/export?format=json" "${output_dir}/plan-export.json"; then
  echo "  saved plan-export.json"
else
  echo "  warning: unable to download plan-export.json (API endpoint not available?)" >&2
fi

if download_asset "/api/plan/${PLAN_ID}/export?format=html" "${output_dir}/plan-export.html"; then
  echo "  saved plan-export.html"
else
  echo "  warning: unable to download plan-export.html (API endpoint not available?)" >&2
fi

mapfile -t module_ids < <(jq -r '.modules[]? | .moduleId // .id // empty' "$plan_json_path")

for module_id in "${module_ids[@]}"; do
  [[ -z "$module_id" ]] && continue

  if download_asset "/api/plan/${PLAN_ID}/module/${module_id}/export?format=json" "${output_dir}/${module_id}.json"; then
    echo "  module ${module_id}: saved JSON report"
  else
    echo "  warning: unable to download JSON for module ${module_id}" >&2
  fi

  if download_asset "/api/plan/${PLAN_ID}/module/${module_id}/export?format=html" "${output_dir}/${module_id}.html"; then
    echo "  module ${module_id}: saved HTML report"
  else
    echo "  warning: unable to download HTML for module ${module_id}" >&2
  fi
done

echo "Report collection complete."
