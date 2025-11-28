#!/usr/bin/env bash
# Usage:
#   LOCAL_CHECK_ONLINE=1 LOCAL_CHECK_STRICT=1 ci/local_check.sh
# Defaults: offline, non-strict.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$REPO_ROOT"

: "${LOCAL_CHECK_ONLINE:=0}"
: "${LOCAL_CHECK_STRICT:=0}"
: "${LOCAL_CHECK_VERBOSE:=0}"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

if [[ "$LOCAL_CHECK_VERBOSE" == "1" ]]; then
  set -x
fi

export CARGO_TERM_COLOR=always

declare -a LOCAL_CHECK_SKIPS=()

need() {
  if command -v "$1" >/dev/null 2>&1; then
    return 0
  fi
  echo "[miss] $1" >&2
  return 1
}

step() {
  printf '\n▶ %s\n' "$*"
}

record_skip() {
  LOCAL_CHECK_SKIPS+=("$1 ($2)")
  echo "[skip] $1 ($2)"
}

run_or_skip() {
  local desc="$1"
  shift || true

  local -a reqs=()
  while [[ "$#" -gt 0 ]]; do
    if [[ "$1" == "--" ]]; then
      shift
      break
    fi
    reqs+=("$1")
    shift
  done

  local reason=""
  local reason_type=""
  local req
  for req in "${reqs[@]}"; do
    case "$req" in
      @online)
        if [[ "$LOCAL_CHECK_ONLINE" != "1" ]]; then
          reason="requires network (set LOCAL_CHECK_ONLINE=1)"
          reason_type="online"
          break
        fi
        ;;
      @file=*)
        local path="${req#@file=}"
        if [[ ! -e "$path" ]]; then
          reason="missing file ${path}"
          reason_type="file"
          break
        fi
        ;;
      @env=*)
        local var="${req#@env=}"
        if [[ -z "${!var:-}" ]]; then
          reason="missing env ${var}"
          reason_type="env"
          break
        fi
        ;;
      @strict)
        if [[ "$LOCAL_CHECK_STRICT" != "1" ]]; then
          reason="enable LOCAL_CHECK_STRICT=1"
          reason_type="strict"
          break
        fi
        ;;
      *)
        if ! need "$req"; then
          reason="missing tool ${req}"
          reason_type="tool"
          break
        fi
        ;;
    esac
  done

  if [[ -n "$reason" ]]; then
    if [[ "$LOCAL_CHECK_STRICT" == "1" && "$reason_type" == "tool" ]]; then
      echo "[fail] $desc ($reason)" >&2
      exit 1
    fi
    record_skip "$desc" "$reason"
    return 0
  fi

  step "$desc"
  if "$@"; then
    return 0
  fi

  local status=$?
  echo "[fail] $desc (exit ${status})" >&2
  exit $status
}

has_make_target() {
  local target="$1"
  if ! command -v make >/dev/null 2>&1; then
    return 1
  fi
  make -n "$target" >/dev/null 2>&1
}

live_oauth_providers() {
  local -a detected=()
  local providers=(GOOGLE MICROSOFT GITHUB)
  local name id_var secret_var redirect_var
  for name in "${providers[@]}"; do
    id_var="OAUTH_${name}_CLIENT_ID"
    secret_var="OAUTH_${name}_CLIENT_SECRET"
    redirect_var="OAUTH_${name}_REDIRECT_URI"
    if [[ -n "${!id_var:-}" && -n "${!secret_var:-}" && -n "${!redirect_var:-}" ]]; then
      detected+=("$name")
    fi
  done
  printf '%s' "${detected[*]-}"
}

HAS_OAUTH_TEST=0
[[ -f tests/oauth.rs ]] && HAS_OAUTH_TEST=1
HAS_AZURE_TEST=0
[[ -f tests/provider_azure.rs ]] && HAS_AZURE_TEST=1
HAS_GOOGLE_TEST=0
[[ -f tests/provider_google.rs ]] && HAS_GOOGLE_TEST=1

step "Environment"
echo "repo      : $REPO_ROOT"
echo "online    : $LOCAL_CHECK_ONLINE"
echo "strict    : $LOCAL_CHECK_STRICT"
echo "verbose   : $LOCAL_CHECK_VERBOSE"

step "Tool versions"
for tool in rustc cargo rustfmt clippy-driver python3 jq docker cloudflared; do
  if command -v "$tool" >/dev/null 2>&1; then
    if "$tool" --version >/dev/null 2>&1; then
      "$tool" --version
    elif "$tool" version >/dev/null 2>&1; then
      "$tool" version
    else
      echo "$tool available"
    fi
  else
    echo "[miss] $tool"
  fi
done

run_or_skip "cargo fmt" cargo rustfmt -- cargo fmt --all -- --check
run_or_skip "cargo clippy" cargo -- cargo clippy --workspace --all-targets -- -D warnings
run_or_skip "cargo build --workspace --locked" cargo -- cargo build --workspace --locked
run_or_skip "cargo build --workspace --all-features" cargo -- cargo build --workspace --all-features
run_or_skip "cargo test --workspace --all-features" cargo -- cargo test --workspace --all-features -- --nocapture

if (( HAS_OAUTH_TEST )); then
  run_or_skip "OAuth mock tests" cargo -- env CI=1 CI_ENABLE_OAUTH_MOCK=1 cargo test --test oauth --features oauth -- --nocapture
  LIVE_PROVIDERS="$(live_oauth_providers)"
  if [[ -n "${LIVE_PROVIDERS:-}" ]]; then
    echo "[info] detected live OAuth credentials for: ${LIVE_PROVIDERS}" >&2
    run_or_skip "OAuth live tests" @online cargo -- env CI=1 CI_ENABLE_OAUTH_LIVE=1 cargo test --test oauth --features oauth -- --nocapture
  else
    record_skip "OAuth live tests" "no OAUTH_* credentials detected"
  fi
else
  record_skip "OAuth suites" "tests/oauth.rs missing"
fi

if (( HAS_AZURE_TEST )); then
  run_or_skip "Provider Azure smoke" @online cargo @env=AZURE_TENANT_ID @env=AZURE_CLIENT_ID @env=AZURE_CLIENT_SECRET -- env CI=1 cargo test -- --ignored --test-threads=1 provider_azure
fi

if (( HAS_GOOGLE_TEST )); then
  run_or_skip "Provider Google smoke" @online cargo @env=GOOGLE_SA_JSON_B64 -- env CI=1 cargo test -- --ignored --test-threads=1 provider_google
fi

if has_make_target conformance.plan; then
  run_or_skip "Hosted OIDF plan (make conformance.plan)" @online make @env=CS_TOKEN -- make conformance.plan
else
  record_skip "Hosted OIDF plan (make conformance.plan)" "make target missing"
fi

# Strict mode optionally re-runs the hosted plan with an explicit PLAN_ID/CS_TOKEN.
if [[ "$LOCAL_CHECK_STRICT" == "1" ]]; then
  if [[ -z "${PLAN_ID:-}" || -z "${CS_TOKEN:-}" ]]; then
    record_skip "Hosted OIDF plan (tunnel)" "set PLAN_ID and CS_TOKEN in .env to run"
  else
    HOSTED_REQS=(@online bash jq curl @file=ci/scripts/run_conformance_hosted_with_tunnel.sh)
    if [[ "${USE_TUNNEL:-1}" != "0" ]]; then
      HOSTED_REQS+=(cloudflared)
    fi
    run_or_skip "Hosted OIDF plan (tunnel)" "${HOSTED_REQS[@]}" -- bash ci/scripts/run_conformance_hosted_with_tunnel.sh
  fi
else
  record_skip "Hosted OIDF plan (tunnel)" "enable LOCAL_CHECK_STRICT=1"
fi

run_or_skip "Crate version scan" cargo jq @file=scripts/version-tools.sh -- bash -c '
  set -euo pipefail
  source scripts/version-tools.sh
  list_crates >/dev/null
'

if [[ -f crates/oauth-mock/Cargo.toml ]]; then
  run_or_skip "cargo publish --dry-run (oauth-mock)" @online cargo @env=CARGO_REGISTRY_TOKEN -- env CARGO_REGISTRY_TOKEN="${CARGO_REGISTRY_TOKEN:-}" cargo publish --dry-run -p oauth-mock
fi

if ((${#LOCAL_CHECK_SKIPS[@]})); then
  printf '\nSkipped steps (%d):\n' "${#LOCAL_CHECK_SKIPS[@]}"
  for entry in "${LOCAL_CHECK_SKIPS[@]}"; do
    printf '  - %s\n' "$entry"
  done
fi

printf '\n[done] local CI checks completed at %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
