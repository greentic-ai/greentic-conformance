#!/usr/bin/env bash
set -euo pipefail

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  cat <<'USAGE'
Usage: wait_for.sh URL [TIMEOUT_SECONDS]

Polls the specified URL until it responds with a successful HTTP status code or
the timeout elapses. Exits with a non-zero status on timeout.
USAGE
  exit 0
fi

URL="${1:-}"
TIMEOUT="${2:-180}"

if [[ -z "$URL" ]]; then
  echo "wait_for.sh: missing URL argument" >&2
  exit 2
fi

DEADLINE=$((SECONDS + TIMEOUT))

while (( SECONDS <= DEADLINE )); do
  if curl --silent --show-error --fail --insecure "$URL" > /dev/null; then
    exit 0
  fi
  sleep 2
done

echo "wait_for.sh: timed out after ${TIMEOUT}s waiting for $URL" >&2
exit 1
