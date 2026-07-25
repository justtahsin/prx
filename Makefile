VERSION ?= 0.1.0
LDFLAGS := -s -w -X main.version=$(VERSION)
GOFLAGS := -trimpath
BIN     := bin
PREFIX  ?= /usr/local

.PHONY: all
all: build

.PHONY: build
build: ## Build prxd (server) and prx (client) for this machine
	@mkdir -p $(BIN)
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN)/prxd ./cmd/prxd
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN)/prx  ./cmd/prx
	@echo "built $(BIN)/prxd and $(BIN)/prx"

.PHONY: test
test: ## Run the test suite
	go test ./...

.PHONY: race
race: ## Run the test suite under the race detector
	go test -race -count=1 ./...

.PHONY: check
check: ## Everything CI would run
	gofmt -l . | tee /dev/stderr | (! read)
	go vet ./...
	go test -race -count=1 ./...

.PHONY: install
install: build ## Install both binaries into $(PREFIX)/bin
	install -Dm755 $(BIN)/prxd $(DESTDIR)$(PREFIX)/bin/prxd
	install -Dm755 $(BIN)/prx  $(DESTDIR)$(PREFIX)/bin/prx
	@echo "installed to $(DESTDIR)$(PREFIX)/bin"
	@echo "next: sudo prxd init && sudo prxd install"

# Cross-compiled clients, for handing a binary to someone on another machine.
# android/arm64 is the plain CLI client; the app comes from the same core via
# gomobile in the next phase.
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 android/arm64

.PHONY: release
release: ## Cross-compile clients (and servers where they make sense)
	@mkdir -p $(BIN)/release
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		ext=""; if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		echo "  $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" \
			-o $(BIN)/release/prx-$$os-$$arch$$ext ./cmd/prx || exit 1; \
		if [ "$$os" = "linux" ]; then \
			GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" \
				-o $(BIN)/release/prxd-$$os-$$arch ./cmd/prxd || exit 1; \
		fi; \
	done
	@echo "release binaries in $(BIN)/release"

# ---------------------------------------------------------------- android

ANDROID_HOME ?= $(HOME)/Android/Sdk

# An ANDROID_NDK_HOME exported as an empty string still counts as "set" to
# make's ?=, which would leave it empty rather than falling back. CI runners
# do export it blank, so test the value instead of whether it is defined.
ifeq ($(strip $(ANDROID_NDK_HOME)),)
ANDROID_NDK_HOME := $(firstword $(wildcard $(ANDROID_HOME)/ndk/*))
endif

AAR := android/app/libs/prxmobile.aar

.PHONY: aar
aar: ## Build the Go client as an Android library (.aar)
	@test -n "$(ANDROID_NDK_HOME)" || { echo "no NDK found under $(ANDROID_HOME)/ndk"; exit 1; }
	@mkdir -p android/app/libs
	ANDROID_HOME=$(ANDROID_HOME) ANDROID_NDK_HOME=$(ANDROID_NDK_HOME) \
	gomobile bind -target=android/arm64,android/arm -androidapi 24 -trimpath \
		-ldflags "-s -w" -javapkg dev.prx -o $(AAR) ./mobile
	@echo "built $(AAR)"

.PHONY: apk
apk: $(AAR) ## Build the Android app (release APK, debug-signed)
	cd android && ./gradlew --quiet assembleRelease
	@ls -1 android/app/build/outputs/apk/release/*.apk

$(AAR):
	$(MAKE) aar

.PHONY: clean
clean: ## Remove build output
	rm -rf $(BIN)
	rm -rf android/build android/app/build

.PHONY: help
help: ## List targets
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'
