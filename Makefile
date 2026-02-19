APP_NAME := awg-split-tunnel
CMD_DIR := ./cmd/awg-split-tunnel
OUT_DIR := ./build
BINARY := $(OUT_DIR)/$(APP_NAME).exe

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

.PHONY: all build clean fmt vet test generate-resource

all: build

build: $(OUT_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD_DIR)
	@echo "Built $(BINARY) ($(VERSION))"

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

clean:
	rm -rf $(OUT_DIR)
	rm -f $(RSRC)

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
