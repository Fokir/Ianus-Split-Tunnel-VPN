APP_NAME := awg-split-tunnel
CMD_DIR := ./cmd/awg-split-tunnel
UPDATER_CMD_DIR := ./cmd/awg-split-tunnel-updater
TEST_CMD_DIR := ./cmd/awg-test
DIAG_CMD_DIR := ./cmd/awg-diag
UI_DIR := ./ui
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

# Shared icon for all binaries.
ICO := ./ui/build/windows/icon.ico

# Windows resource files (manifest + icon → .syso).
RSRC := $(CMD_DIR)/rsrc_windows_amd64.syso
UPDATER_RSRC := $(UPDATER_CMD_DIR)/rsrc_windows_amd64.syso
TEST_RSRC := $(TEST_CMD_DIR)/rsrc_windows_amd64.syso
DIAG_RSRC := $(DIAG_CMD_DIR)/rsrc_windows_amd64.syso
UI_RSRC := $(UI_DIR)/rsrc_windows_amd64.syso

.PHONY: all build updater test-runner clean fmt vet test \
	generate-resource generate-updater-resource generate-test-resource \
	generate-diag-resource generate-ui-resource generate-all-resources

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
	rm -f $(DIAG_RSRC)
	rm -f $(UI_RSRC)

fmt:
	go fmt ./...

vet:
	go vet ./...

test:
	go test ./...

# Generate Windows resources (.syso) from manifest + icon.
# Requires: go install github.com/akavel/rsrc@latest
generate-resource:
	rsrc -manifest $(CMD_DIR)/app.manifest -ico $(ICO) -o $(RSRC)

generate-updater-resource:
	rsrc -manifest $(UPDATER_CMD_DIR)/app.manifest -ico $(ICO) -o $(UPDATER_RSRC)

generate-test-resource:
	rsrc -manifest $(TEST_CMD_DIR)/app.manifest -ico $(ICO) -o $(TEST_RSRC)

generate-diag-resource:
	rsrc -manifest $(DIAG_CMD_DIR)/app.manifest -ico $(ICO) -o $(DIAG_RSRC)

generate-ui-resource:
	rsrc -manifest $(UI_DIR)/build/windows/wails.exe.manifest -ico $(ICO) -o $(UI_RSRC)

generate-all-resources: generate-resource generate-updater-resource generate-test-resource generate-diag-resource generate-ui-resource
