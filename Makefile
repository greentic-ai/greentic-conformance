CONFORMANCE_HOSTED_ENV ?= ci/env/conformance.hosted.env

-include .env
-include $(CONFORMANCE_HOSTED_ENV)
export

PLAN ?= oidcc-client-basic-certification-test-plan
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
	CS_URL=$(CS_URL) \
	CS_TOKEN=$(CS_TOKEN) \
	PLAN=$(PLAN) \
	ALIAS=$(ALIAS) \
	CLIENT_REG=$(CLIENT_REG) \
	REQUEST_TYPE=$(REQUEST_TYPE) \
	CONFIG_JSON=$(CONFIG_JSON) \
	PLAN_ID=$(PLAN_ID) \
	USE_TUNNEL=$(USE_TUNNEL) \
	RP_LOCAL_URL=$(RP_LOCAL_URL) \
	RP_BASE=$(RP_BASE) \
	bash ci/scripts/run_conformance_hosted_with_tunnel.sh
