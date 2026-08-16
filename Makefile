BINARY  := llm-security-monitor
GO      := go
LDFLAGS := -ldflags="-s -w" -trimpath

.PHONY: build test bench lint docker docker-up docker-test clean help

## build: compile static binary (default)
build:
	$(GO) build $(LDFLAGS) -o $(BINARY) ./cmd/proxy

## test: run full test suite with race detector
test:
	$(GO) test -race -count=1 -timeout=60s ./...

## bench: run all benchmarks (3 s per benchmark)
bench:
	$(GO) test -bench=. -benchmem -benchtime=3s -run='^$$' \
		./internal/detector/ ./internal/nlp/

## lint: run golangci-lint
lint:
	golangci-lint run --timeout=3m

## vet: run go vet
vet:
	$(GO) vet ./...

## docker: build Docker image
docker:
	docker build -t $(BINARY):latest .

## docker-up: start proxy + Ollama via docker compose
docker-up:
	docker compose up

## docker-test: run integration tests inside Docker
docker-test:
	docker compose --profile test up --abort-on-container-exit tester

## clean: remove compiled binary
clean:
	rm -f $(BINARY)

## run-block: start proxy in block mode (alert-only if Ollama not running)
run-block:
	BLOCK_MODE=true ./$(BINARY)

## run-sanitize: start proxy in sanitize mode
run-sanitize:
	SANITIZE_MODE=true ./$(BINARY)

## run-debug: start proxy with debug logging
run-debug:
	BLOCK_MODE=true LOG_LEVEL=DEBUG ./$(BINARY)

## help: show this help
help:
	@grep -E '^##' $(MAKEFILE_LIST) | sed 's/## /  /'

.DEFAULT_GOAL := build
