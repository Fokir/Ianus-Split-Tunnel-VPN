APP_NAME := awg-split-tunnel
CMD_DIR := ./cmd/awg-split-tunnel
UPDATER_CMD_DIR := ./cmd/awg-split-tunnel-updater
TEST_CMD_DIR := ./cmd/awg-test
OUT_DIR := ./build
BINARY := $(OUT_DIR)/$(APP_NAME).exe
UPDATER_BINARY := $(OUT_DIR)/$(APP_NAME)-updater.exe
TEST_BINARY := $(OUT_DIR)/awg-test.exe

# Version info embedded via ldflags.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -s -w \
	-X 'main.version=$(VERSION)' \
	-X 'main.commit=$(COMMIT)' \
	-X 'main.buildDate=$(DATE)'

# Windows resource (manifest for admin elevation).
RSRC := $(CMD_DIR)/rsrc_windows_amd64.syso
UPDATER_RSRC := $(UPDATER_CMD_DIR)/rsrc_windows_amd64.syso
TEST_RSRC := $(TEST_CMD_DIR)/rsrc_windows_amd64.syso

.PHONY: all build updater test-runner clean fmt vet test generate-resource generate-updater-resource generate-test-resource

all: build updater

build: $(OUT_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD_DIR)
	@echo "Built $(BINARY) ($(VERSION))"

updater: $(OUT_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(UPDATER_BINARY) $(UPDATER_CMD_DIR)
	@echo "Built $(UPDATER_BINARY) ($(VERSION))"

test-runner: $(OUT_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(TEST_BINARY) $(TEST_CMD_DIR)
	@echo "Built $(TEST_BINARY) ($(VERSION))"

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

clean:
	rm -rf $(OUT_DIR)
	rm -f $(RSRC)
	rm -f $(UPDATER_RSRC)
	rm -f $(TEST_RSRC)

fmt:
	go fmt ./...

vet:
	go vet ./...

test:
	go test ./...

# Generate Windows resource (.syso) from manifest.
# Requires: go install github.com/akavel/rsrc@latest
generate-resource:
	rsrc -manifest $(CMD_DIR)/app.manifest -o $(RSRC)

generate-updater-resource:
	rsrc -manifest $(UPDATER_CMD_DIR)/app.manifest -o $(UPDATER_RSRC)

generate-test-resource:
	rsrc -manifest $(TEST_CMD_DIR)/app.manifest -o $(TEST_RSRC)
