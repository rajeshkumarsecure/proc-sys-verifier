BINARY := psv
GO ?= go
GOFLAGS ?=
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: all build test test-integration vet fmt bpf

all: build

build:
	mkdir -p bin
	$(GO) build $(GOFLAGS) -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY) ./cmd/psv

test:
	$(GO) test $(GOFLAGS) ./...
	bash scripts/test-setup.sh

test-integration:
	$(GO) test $(GOFLAGS) -tags integration ./...

vet:
	$(GO) vet $(GOFLAGS) ./...

fmt:
	$(GO) fmt ./...

bpf:
	$(GO) generate ./internal/watch/...
