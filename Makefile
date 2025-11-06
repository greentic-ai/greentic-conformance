-include .env
export

ALIAS ?= greentic-rp
CLIENT_REG ?= dynamic_client
REQUEST_TYPE ?= plain_http_request
CONFIG_JSON ?= ci/plans/examples/rp-code-pkce-basic.config.json
USE_TUNNEL ?= 1
RP_LOCAL_URL ?= http://localhost:8080
CS_URL ?= https://www.certification.openid.net

.PHONY: test e2e ci conformance.plan

test:
	cargo test --workspace --all-features -- --nocapture

e2e:
	CI_ENABLE_OAUTH_MOCK=1 cargo test --test oauth --features oauth -- --nocapture

ci:
	./scripts/ci.sh

conformance.plan:
	@set -a; . ./.env; set +a; \
	bash ci/scripts/run_conformance_hosted_with_tunnel.sh || { \
		status=$$?; \
		echo >&2 "[make] conformance.plan failed (exit $$status). See logs above for details, then verify your .env settings (CS_TOKEN, RP_BASE, etc.)."; \
		exit $$status; \
	}
