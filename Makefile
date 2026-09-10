BINARY := gh-repo-lint
REPO   ?= $(shell git remote get-url origin 2>/dev/null | sed -E 's#.*[:/]([^/]+/[^/]+?)(\.git)?$$#\1#')

GO       ?= go
GOFLAGS  ?=
COVERAGE := coverage.out

.DEFAULT_GOAL := build

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[1m%-12s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the extension binary
	$(GO) build $(GOFLAGS) -o $(BINARY) .

.PHONY: test
test: ## Run the tests with the race detector
	$(GO) test -race ./...

.PHONY: cover
cover: ## Run the tests and open the coverage report
	$(GO) test -coverprofile=$(COVERAGE) ./...
	$(GO) tool cover -func=$(COVERAGE) | tail -1
	$(GO) tool cover -html=$(COVERAGE)

.PHONY: fmt
fmt: ## Format the source
	gofmt -w .

.PHONY: vet
vet: ## Run go vet
	$(GO) vet ./...

.PHONY: check
check: ## Everything CI runs: formatting, vet, tests
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "These files need gofmt:"; echo "$$unformatted"; exit 1; \
	fi
	$(GO) vet ./...
	$(GO) test -race -cover ./...

.PHONY: tidy
tidy: ## Tidy go.mod and go.sum
	$(GO) mod tidy

# Pass flags through as ARGS, e.g. make run ARGS="--repo cli/cli --level basic"
.PHONY: run
run: build ## Run against a repository (ARGS="--repo owner/name")
	./$(BINARY) $(ARGS)

.PHONY: self
self: build ## Lint this repository with the freshly built binary
	@test -n "$(REPO)" || { echo "no git remote; use: make run ARGS='--repo owner/name'"; exit 1; }
	./$(BINARY) --repo $(REPO) --fail-on none

.PHONY: install
install: ## Install as a local gh extension
	gh extension install .

.PHONY: uninstall
uninstall: ## Remove the local gh extension
	gh extension remove repo-lint

.PHONY: clean
clean: ## Remove build artefacts
	rm -f $(BINARY) $(BINARY).exe $(COVERAGE)
