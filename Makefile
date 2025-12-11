# Copyright (c) The Kowabunga Project
# Apache License, Version 2.0 (see LICENSE or https://www.apache.org/licenses/LICENSE-2.0.txt)
# SPDX-License-Identifier: Apache-2.0

PKG_NAME=github.com/kowabunga-cloud/kobra/kobra
VERSION=0.2.0

# Make sure GOPATH is NOT set to this folder or we'll get an error "$GOPATH/go.mod exists but should not"
#export GOPATH = ""
export GO111MODULE = on
BINDIR = bin

GOLINT = $(BINDIR)/golangci-lint
GOLINT_VERSION = v2.4.0

GOVULNCHECK = $(BINDIR)/govulncheck
GOVULNCHECK_VERSION = v1.1.4

GOSEC = $(BINDIR)/gosec
GOSEC_VERSION = v2.22.8

GORELEASER = $(BINDIR)/goreleaser
GORELEASER_VERSION = v2.11.2

PKGS = $(shell go list ./...)

V = 0
Q = $(if $(filter 1,$V),,@)
M = $(shell printf "\033[34;1m▶\033[0m")

.PHONY: all
all: mod fmt vet lint build ; @ ## Do all
	$Q echo "done"

# This target grabs the necessary go modules
.PHONY: mod
mod: ; $(info $(M) collecting modules…) @
	$Q go mod download
	$Q go mod tidy

# Updates all go modules
update: ; $(info $(M) updating modules…) @
	$Q go get -u ./...
	$Q go mod tidy

# This target build the binaries
# its a PHONY because we want to build all the time
.PHONY: build
build: ; $(info $(M) building executables…) @ ## Build binaries
	$Q mkdir -p $(BINDIR)
	$Q go build \
		-gcflags="kobra/...=-e" \
		-ldflags='-s -w -X $(PKG_NAME).version=$(VERSION)' \
		-o $(BINDIR) ./...

.PHONY: release
release: mod fmt vet lint get-goreleaser ; @
	$Q PKG_NAME=$(PKG_NAME) VERSION=$(VERSION) $(GORELEASER) build --snapshot --clean

.PHONY: get-lint
get-lint: ; $(info $(M) downloading go-lint…) @
	$Q test -x $(GOLINT) || curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s $(GOLINT_VERSION)

.PHONY: lint
lint: get-lint ; $(info $(M) running go-lint…) @
	$Q $(GOLINT) run ./... ; exit 0

.PHONY: get-govulncheck
get-govulncheck: ; $(info $(M) downloading govulncheck…) @
	$Q test -x $(GOVULNCHECK) || GOBIN="$(PWD)/$(BINDIR)/" go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

.PHONY: vuln
vuln: get-govulncheck ; $(info $(M) running govulncheck…) @ ## Check for known vulnerabilities
	$Q $(GOVULNCHECK) ./... ; exit 0

.PHONY: get-gosec
get-gosec: ; $(info $(M) downloading gosec…) @
	$Q test -x $(GOSEC) || GOBIN="$(PWD)/$(BINDIR)/" go install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)

.PHONY: sec
sec: get-gosec ; $(info $(M) running gosec…) @ ## AST / SSA code checks
	$Q $(GOSEC) -terse -exclude=G101,G302,G115 ./... ; exit 0

.PHONY: get-goreleaser
get-goreleaser: ; $(info $(M) downloading go-releaser…) @
	$Q test -x $(GORELEASER) || curl -sL https://github.com/goreleaser/goreleaser/releases/download/$(GORELEASER_VERSION)/goreleaser_$(shell uname -s)_$(shell uname -m).tar.gz | tar -xz -C "$(PWD)/$(BINDIR)/"

# This target run the go vet which do some static analysis
.PHONY: vet
vet: ; $(info $(M) running go vet…) @ ## Run go vet
	$Q go vet $(PKGS) ; exit 0

# This target run the code format tool
.PHONY: fmt
fmt: ; $(info $(M) running go fmt…) @ ## Run go fmt on all source files
	$Q go fmt $(PKGS)

.PHONY: tests
tests: ; $(info $(M) running test suite…) @
	$Q go test ./... -count=1 -coverprofile=coverage.txt

PHONY: deb
deb: mod build ; $(info $(M) building debian package…) @
	$Q VERSION=$(VERSION) ./debian.sh

# This target clean all the generated files
.PHONY: clean
clean: ; $(info $(M) cleaning…)	@ ## Cleanup everything
	@rm -rf $(BINDIR)/*
