.DEFAULT_GOAL := build

GOCACHE ?= $(CURDIR)/.cache/go-build
BIN_DIR := bin
BIN := $(BIN_DIR)/digi-credentials

.PHONY: build test vet check clean

build:
	mkdir -p $(BIN_DIR) $(GOCACHE)
	GOCACHE=$(GOCACHE) mise exec -- go build -o $(BIN) ./cmd/digi-credentials

test:
	mkdir -p $(GOCACHE)
	GOCACHE=$(GOCACHE) mise exec -- go test ./...

vet:
	mkdir -p $(GOCACHE)
	GOCACHE=$(GOCACHE) mise exec -- go vet ./...

check: test vet

clean:
	rm -rf $(BIN_DIR) .cache
