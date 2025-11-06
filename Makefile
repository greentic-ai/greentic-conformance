CONFORMANCE_REF ?= release-v5.1.35
CS_DIR := $(CURDIR)/.cache/conformance-suite
DOCKER_CONFIG_DIR := $(CURDIR)/.docker
export CONFORMANCE_REF
export CS_DIR

CONFORMANCE_PLAN ?= oidcc-client-basic-certification-test-plan
ALIAS ?= greentic-rp
CONFIG_JSON ?= ci/plans/examples/rp-code-pkce-basic.config.json
CLIENT_REG ?= dynamic_client
REQUEST_TYPE ?= plain_http_request

.PHONY: test e2e ci conformance.fetch conformance.mvn conformance.build conformance.up conformance.plan conformance.reports conformance.down conformance.logs conformance.run conformance.full

PLAN ?= rp-code-pkce-basic

test:
	cargo test --workspace --all-features -- --nocapture

e2e:
	CI_ENABLE_OAUTH_MOCK=1 cargo test --test oauth --features oauth -- --nocapture

ci:
	./scripts/ci.sh

conformance.fetch:
	@mkdir -p .cache
	@if [ ! -d "$(CS_DIR)/.git" ]; then \
		git clone --depth 1 --branch $(CONFORMANCE_REF) https://gitlab.com/openid/conformance-suite.git $(CS_DIR); \
	else \
		git -C $(CS_DIR) fetch --depth 1 origin $(CONFORMANCE_REF) && git -C $(CS_DIR) checkout -q $(CONFORMANCE_REF); \
	fi

conformance.mvn: conformance.fetch
	@echo "Building conformance-suite with Maven (skip tests)…"
	@docker run --rm -u $$(id -u):$$(id -g) \
		-v $(CS_DIR):/ws -w /ws maven:3-eclipse-temurin-17 \
		mvn -q -DskipTests -Dmaven.test.skip=true package

conformance.build: conformance.mvn
	@echo "Building docker images from upstream sources @ $(CONFORMANCE_REF)…"
	mkdir -p $(DOCKER_CONFIG_DIR)
	mkdir -p $(CURDIR)/.home
	HOME=$(CURDIR)/.home DOCKER_CONFIG=$(DOCKER_CONFIG_DIR) docker compose -f ci/docker/compose.conformance.yml build --pull

conformance.up: conformance.build
	HOME=$(CURDIR)/.home DOCKER_CONFIG=$(DOCKER_CONFIG_DIR) docker compose -f ci/docker/compose.conformance.yml up -d --wait
	@echo "✅ Open https://localhost:8443/ (self-signed). Ref: $(CONFORMANCE_REF)"

conformance.plan:
	./ci/scripts/run_conformance_plan.sh $(PLAN)

conformance.run:
	CS_URL=$(CS_URL) \
	CS_TOKEN=$(CS_TOKEN) \
	PLAN=$(CONFORMANCE_PLAN) \
	ALIAS=$(ALIAS) \
	CONFIG_JSON=$(CONFIG_JSON) \
	RP_METADATA_URL=$(RP_METADATA_URL) \
	CLIENT_REG=$(CLIENT_REG) \
	REQUEST_TYPE=$(REQUEST_TYPE) \
	bash ./ci/scripts/auto_run_conformance_plan.sh

conformance.full: conformance.plan conformance.run

conformance.reports:
	./ci/scripts/collect_reports.sh

conformance.down:
	docker compose -f ci/docker/compose.conformance.yml down -v

conformance.logs:
	docker compose -f ci/docker/compose.conformance.yml logs -f
