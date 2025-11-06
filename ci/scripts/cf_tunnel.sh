#!/usr/bin/env bash
set -euo pipefail

RP_LOCAL_URL="${RP_LOCAL_URL:-http://localhost:8080}"
CF_BIN="${CF_BIN:-cloudflared}"
OUT_ENV="${OUT_ENV:-.cf-tunnel.env}"
LOG="${LOG:-.cf-tunnel.log}"

if ! command -v "${CF_BIN}" >/dev/null 2>&1; then
  echo "[cf] cloudflared not found. Install it from https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/install-and-setup/installation/"
  exit 1
fi

: > "${LOG}"
"${CF_BIN}" tunnel --no-autoupdate --url "${RP_LOCAL_URL}" > "${LOG}" 2>&1 &
CF_PID=$!
trap 'kill "${CF_PID}" 2>/dev/null || true' EXIT
echo "[cf] starting tunnel to ${RP_LOCAL_URL} (pid=${CF_PID})..."

TUNNEL_URL=""
for i in {1..60}; do
  if grep -Eo 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' "${LOG}" >/dev/null; then
    TUNNEL_URL=$(grep -Eo 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' "${LOG}" | head -n1)
    break
  fi
  sleep 0.5
done

if [[ -z "${TUNNEL_URL}" ]]; then
  echo "[cf] failed to detect tunnel URL. Last log lines:"
  tail -n 50 "${LOG}" || true
  exit 1
fi

echo "[cf] tunnel ready: ${TUNNEL_URL}"
echo "RP_BASE=${TUNNEL_URL}" > "${OUT_ENV}"
echo "[cf] wrote ${OUT_ENV} (RP_BASE=${TUNNEL_URL})"
