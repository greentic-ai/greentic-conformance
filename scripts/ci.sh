#!/usr/bin/env bash
set -euo pipefail

exec cargo fmt --all -- --check && cargo clippy --all -- -D warnings
