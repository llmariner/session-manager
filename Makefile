.PHONY: default
default: test

include common.mk

.PHONY: test
test: go-test-all

.PHONY: lint
lint: go-lint-all git-clean-check

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
