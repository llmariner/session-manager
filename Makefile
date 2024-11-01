.PHONY: default
default: test

include common.mk

.PHONY: test
test: go-test-all

.PHONY: lint
lint: go-lint-all helm-lint git-clean-check

.PHONY: generate
generate: buf-generate-all

.PHONY: build-server
build-server:
	go build -o ./bin/server ./server/cmd/

.PHONY: build-agent
build-agent:
	go build -o ./bin/agent ./agent/cmd/

.PHONY: build-docker-server
build-docker-server:
	docker build --build-arg TARGETARCH=amd64 -t llmariner/session-manager-server:latest -f build/server/Dockerfile .

.PHONY: build-docker-agent
build-docker-agent:
	docker build --build-arg TARGETARCH=amd64 -t llmariner/session-manager-agent:latest -f build/agent/Dockerfile .

.PHONY: check-helm-tool
check-helm-tool:
	@command -v helm-tool >/dev/null 2>&1 || $(MAKE) install-helm-tool

.PHONY: install-helm-tool
install-helm-tool:
	go install github.com/cert-manager/helm-tool@latest

.PHONY: generate-chart-schema
generate-chart-schema: generate-chart-schema-server generate-chart-schema-agent

.PHONY: generate-chart-schema-server
generate-chart-schema-server: check-helm-tool
	@cd ./deployments/server && helm-tool schema > values.schema.json

.PHONY: generate-chart-schema-agent
generate-chart-schema-agent: check-helm-tool
	@cd ./deployments/agent && helm-tool schema > values.schema.json

.PHONY: helm-lint
helm-lint: helm-lint-server helm-lint-agent

.PHONY: helm-lint-server
helm-lint-server: generate-chart-schema-server
	cd ./deployments/server && helm-tool lint
	helm lint ./deployments/server

.PHONY: helm-lint-agent
helm-lint-agent: generate-chart-schema-agent
	cd ./deployments/agent && helm-tool lint
	helm lint ./deployments/agent
